import collections
import dataclasses
import errno
import os
import sys
import threading
import time
import typing
from argparse import ArgumentParser
from base64 import b64decode, b64encode
from collections.abc import Buffer, Iterator, Sized
from dataclasses import dataclass, field
from datetime import datetime
from glob import escape
from itertools import islice
from shlex import quote
from pathlib import Path as PPath
import re

from serial import Serial
from strip_ansi import strip_ansi
from userspacefs import mount_and_run_fs
import userspacefs.abc as fsabc
from userspacefs.abc import PathT, Directory
from userspacefs.memoryfs import StatVFSDC
from userspacefs.path_common import Path
from userspacefs.util_dumpster import (
	PositionIO,
	null_context,
	quick_container,
	datetime_now,
	NewStat,
	NewDirectory,
	WriteableBuffer,
	ReadableBuffer,
	OldDirectoryProtocol,
	OldDirStatProtocol,
	datetime_from_ts,
)

import logging

log = logging.getLogger(__name__)

# Log everything
logging.basicConfig(level=logging.DEBUG)

# Stat = collections.namedtuple(
# 	"Stat", ["name", "mtime", "type", "size", "id", "ctime", "rev", "attrs"]
# )


@dataclass
class Stat:
	mtime: datetime
	type: str
	size: int
	ctime: datetime
	name: str = None
	children: any = field(default_factory=lambda: [])
	attrs: list[str] = field(default_factory=lambda: [])
	id: PathT = None
	rev: list[str] = field(default_factory=lambda: [])

	def __post_init__(self):
		self.attrs = [field_.name for field_ in dataclasses.fields(self.__class__)]


try:
	O_ACCMODE = os.O_ACCMODE
except AttributeError:
	if sys.platform == "win32":
		O_ACCMODE = 3
	else:
		raise

file_type_regex = r"regular.* file"


class SerialClient(Serial):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

		# Flush
		self.read_all()

		self.prompt = b":~$ "

		self.lock = threading.Lock()

	def terminal_escape(self, text: str) -> str:
		return f"${quote(text)}"

	def read_lines(self, num_lines: int) -> list[str]:
		lines = []

		for _ in range(num_lines):
			output = self.read_until(b"\n").decode()
			output = output.rstrip("\r\n")

			lines.append(output)

		return lines

	def discard_lines(self, num_lines: int) -> None:
		for _ in range(num_lines):
			self.read_until(b"\n")

	def read_line(self) -> str:
		return self.read_lines(1)[0]

	def send_command(self, command: str) -> None:
		log.debug(f"Sending command: {command}")

		command = command.encode() + b"\n"

		# Send command
		self.write(command)

		# Discard the echo
		self.discard_lines(command.count(b"\n"))
		self.read_until(b"\r")

	def discard_prompt(self) -> None:
		self.read_until(self.prompt)

	def query_one_line(self, command: str) -> str:
		self.send_command(command)

		# Read output
		output = self.read_line()

		log.debug(f"Received output for {command}: {output}")

		self.discard_prompt()

		return output

	def query_x_lines(self, command: str, num_lines: int) -> list[str]:
		self.send_command(command)

		# Read output
		output = self.read_lines(num_lines)

		self.discard_prompt()

		return output

	def query_multiple_lines(self, command: str) -> list[str]:
		self.send_command(command)

		# Read output
		output = self.read_until(self.prompt).decode()

		output = output.split("\n")

		# Discard prompt
		output = output[:-1]

		output = [line.rstrip("\r\n") for line in output]

		log.debug(f"Received output for {command}: {'\n'.join(output)}")

		return output

	def query_no_output(self, command: str) -> None:
		log.debug(f"Sending command: {command}")

		self.send_command(command)

		self.discard_prompt()


class _File(PositionIO):
	def __init__(self, path: str, mode: int, type: str, serial: SerialClient):
		super().__init__()

		self.path = path
		self.mode = mode
		self.type = type

		self.serial = serial

	def preadinto(self, buf_: WriteableBuffer, offset: int) -> int:
		if not self.readable():
			raise OSError(errno.EBADF, os.strerror(errno.EBADF))

		if self.type == "directory":
			raise OSError(errno.EISDIR, os.strerror(errno.EISDIR))

		bufm = memoryview(buf_)
		size = len(bufm)

		with self.serial.lock:
			response = self.serial.query_one_line(
				# TODO: Skip might have been seek in older versions of Linux https://stackoverflow.com/questions/2017285/how-to-extract-specific-bytes-from-a-file-using-unix#comment13831652_2017355
				f"dd if={escape(self.path)} skip={offset} count={size} status=none | base64 -w0 && echo"
			)

		response = b64decode(response)

		response_size = len(response)

		bufm[:response_size] = response

		return response_size

	def readable(self) -> bool:
		return (self.mode & O_ACCMODE) in (os.O_RDONLY, os.O_RDWR)

	# def _file_length(self) -> int:
	# 	response = serial_query(
	# 		# TODO: Slightly different -c argument should be used for MacOS
	# 		f'stat -c %s "{self.path}"'
	# 	)
	#
	# 	response = response.strip()
	# 	size = int(response)
	#
	# 	return size

	def pwrite(self, buf: ReadableBuffer, offset: int) -> int:
		if not self.writable():
			raise OSError(errno.EBADF, os.strerror(errno.EBADF))

		# TODO: Check if write conflicts will occur

		with self.serial.lock:
			self.serial.query_no_output(
				f"base64 -d <<< '{b64encode(buf).decode()}' | dd of={escape(self.path)} bs=1 seek={offset} conv=notrunc status=none"
			)

			# # TODO: Pad with null bytes if there is a gap between the end of the file and the offset
			# self.serial.send_command(
			# 	f"echo R; base64 -d | dd of={escape(self.path)} bs=1 seek={offset} conv=notrunc status=none"
			# )
			#
			# # pyserial read until newline
			# response = self.serial.read_line()
			#
			# # TODO: Check if ready signal is needed, or if .flush() is enough, or not necessary either
			# if response != "R":
			# 	# TODO: Check if this type of error is correct
			# 	raise OSError(errno.EIO, os.strerror(errno.EIO))
			#
			# # Stream Base64
			# self.serial.write(b64encode(buf))
			#
			# self.serial.write(b"\x04")  # Interrupt
			#
			# # TODO: Catch write errors, such as disk full, file not found, readonly
			#
			# # Wait for termination, discarding prompt
			# self.serial.discard_prompt()

		return len(typing.cast(Sized, buf))

	def writable(self) -> bool:
		return (self.mode & O_ACCMODE) in (os.O_WRONLY, os.O_RDWR)

	def ptruncate(self, offset: int) -> int:
		if not self.writable():
			raise OSError(errno.EBADF, os.strerror(errno.EBADF))

		with self.serial.lock:
			# If there is a gap between the end of the file and the offset, it will be filled with null bytes
			self.serial.query_no_output(f'truncate -s {offset} "{self.path}"')

		# New file size
		return offset


class _Directory(OldDirectoryProtocol):
	def __init__(self, path: Path, serial: SerialClient):
		self.path = path
		self.serial = serial

		delimiter = self.serial.terminal_escape("\037")  # ASCII unit seperator
		suffix = "\0"  # Null terminator

		delimiter = "MOUNTSERIALDELIMITER"

		with self.serial.lock:
			# TODO: Slightly different -c argument should be used for MacOS
			# TODO: Stream contents
			contents = self.serial.query_multiple_lines(
				# f'd={delimiter}; find {quote(str(path))} -mindepth 1 -maxdepth 1 -exec stat -c "%n$d%s$d%F$d%Y$d%Z" "{{}}" \\;'
				f'find {quote(str(path))} -mindepth 1 -maxdepth 1 -exec stat -c "%n{delimiter}%s{delimiter}%F{delimiter}%Y{delimiter}%Z" "{{}}" \\;'
			)

		files = []

		for item in contents:
			name, size, file_type, mtime, ctime = item.split(delimiter)

			name = PPath(name).name

			log.debug(f"Found {name}")

			if file_type == "symbolic link":
				# TODO: Handle symbolic links
				log.debug(f"Skipping symbolic link: {name}")
				continue

			if file_type == "special":
				log.debug(f"Skipping special file: {name}")
				continue

			if re.match(file_type_regex, file_type) is not None:
				file_type = "file"

			files.append(
				Stat(
					name=name,
					mtime=datetime.fromtimestamp(int(mtime)),
					ctime=datetime.fromtimestamp(int(ctime)),
					type=file_type,
					size=int(size),
					# TODO: Remove these
					id=name,
					rev=[],
					children=12,
				)
			)

		self._iter = iter(files)

	def close(self) -> None:
		pass

	def read(self) -> typing.Optional[Stat]:
		try:
			return next(self)
		except StopIteration:
			return None

	def __iter__(self) -> typing.Self:
		return self

	def __next__(self) -> Stat:
		return next(self._iter)

	def readmany(self, size: typing.Optional[int] = None) -> typing.List[Stat]:
		ret = typing.cast(Iterator[Stat], self)
		if size is not None:
			ret = islice(ret, size)
		return list(ret)


class FileSystem(fsabc.FileSystemG[Path, _File]):
	def __init__(self, *args, **kwargs):
		self.serial = SerialClient(*args, **kwargs)

	def _filename_norm(self, filename: str) -> str:
		return filename.lower()

	def create_path(self, *parts: str) -> Path:
		return Path.root_path(fn_norm=self._filename_norm).joinpath(*parts)

	def fstat(self, fobj: _File) -> NewStat:
		return self.stat(fobj.path)

	def stat(self, path: Path | str) -> NewStat:
		delimiter = self.serial.terminal_escape("\037")  # ASCII unit seperator
		suffix = "\0"  # Null terminator

		# log.debug("Send stat command for path: %s", path)
		#
		# log.debug("RESPONSE" + self.serial.query_one_line(f"echo ABC"))

		delimiter = "MOUNTSERIALDELIMITER"

		with self.serial.lock:
			# TODO: Slightly different -c argument should be used for MacOS
			response = self.serial.query_one_line(
				# f'd={delimiter}; stat -c "%s$d%F$d%Y$d%Z" {escape(str(path))}'
				f'stat -c "%s:%F:%Y:%Z" {escape(str(path))}'
			)

		if response.startswith("stat: cannot statx"):
			# This means the file does not exist
			raise OSError(errno.ENOENT, os.strerror(errno.ENOENT))

		# log.debug("Received stat response: %s", response)

		size, file_type, mtime, ctime = response.split(":")

		return NewStat(
			Stat(
				name=None,
				mtime=datetime.fromtimestamp(int(mtime)),
				ctime=datetime.fromtimestamp(int(ctime)),
				type=file_type,
				size=int(size),
				# TODO: Remove these
				id=path,
				rev=[],
				children=12,
			)
		)

	def close(self) -> None:
		pass

	def open(
		self, path: Path, mode: int = os.O_RDONLY, directory: bool = False
	) -> _File:
		file_type = "directory" if directory else "file"

		# TODO: Do we need checks for being a directory?
		# TODO: Do we need checks for permissions?

		return _File(
			path=str(path),
			mode=mode,
			type=file_type,
			serial=self.serial,
		)

	def preadinto(self, handle: _File, buf: Buffer, offset: int) -> int:
		return handle.preadinto(buf, offset)

	def pwrite(self, handle: _File, data: Buffer, offset: int) -> int:
		return handle.pwrite(data, offset)

	def fsync(self, _: _File) -> None:
		# We don't need to do anything here because the serial connection always directly writes
		pass

	def _get_is_directory(self, path: Path) -> bool:
		with self.serial.lock:
			response = self.serial.query_one_line(
				f'[ -d {escape(str(path))} ] && echo "Y" || echo "N"'
			)

		return response == "Y"

	def open_directory(self, path: Path) -> NewDirectory:
		is_directory = self._get_is_directory(path)

		if not is_directory:
			raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))

		return NewDirectory(_Directory(path, self.serial))

	def unlink(self, path: Path) -> None:
		with self.serial.lock:
			self.serial.query_one_line(f"rm -f {escape(str(path))}")

	def mkdir(self, path: Path) -> None:
		with self.serial.lock:
			self.serial.query_one_line(f'mkdir -p "{escape(str(path))}')

	def rmdir(self, path: Path) -> None:
		with self.serial.lock:
			self.serial.query_one_line(f"rm -rf {escape(str(path))}")

	def replace(self, old_path: Path, new_path: Path) -> None:
		with self.serial.lock:
			self.serial.query_one_line(
				f"mv -f {escape(str(old_path))} {escape(str(new_path))}"
			)

	def statvfs(self) -> StatVFSDC:
		with self.serial.lock:
			response = self.serial.query_one_line('stat -f -c "%s %b %a" /')

		# log.debug("Received statvfs response: %s", response)
		# log.debug("END RESPONSE")

		frsize, blocks, bavail = map(int, response.split())

		return StatVFSDC(
			f_frsize=frsize,
			f_blocks=blocks,
			f_bavail=bavail,
		)

	def futimes(
		self, handle: _File, times: typing.Optional[typing.Tuple[float, float]] = None
	) -> None:
		if times is not None:
			new_mtime_ts = times[1]
		else:
			new_mtime_ts = time.time()

		new_mtime_ts = datetime_from_ts(new_mtime_ts)

		with self.serial.lock:
			self.serial.query_one_line(
				f'touch -m -d "{new_mtime_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}" "{handle.path}"'
			)


def make_fs(args: typing.Dict[str, typing.Any]) -> FileSystem:
	# log.debug("Creating filesystem")
	return FileSystem(**args)


def main():
	parser = ArgumentParser()

	parser.add_argument("port", type=str)
	parser.add_argument("baud_rate", type=int)
	parser.add_argument("mount_point", type=str)
	# TODO: Add other arguments for pyserial https://pythonhosted.org/pyserial/pyserial_api.html#serial.Serial.__init__

	args = parser.parse_args()

	mount_and_run_fs(
		display_name=args.port,
		create_fs_params=(
			f"mount_serial.{make_fs.__name__}",
			{
				"port": args.port,
				"baudrate": str(args.baud_rate),
			},
		),
		mount_point=args.mount_point,
		foreground=True,
	)

	# serial = Serial(
	# 	port=args.port,
	# 	baudrate=args.baud_rate,
	# )
