import collections
import errno
import os
import sys
import time
import typing
from argparse import ArgumentParser
from base64 import b64decode, b64encode
from collections.abc import Buffer, Iterator
from datetime import datetime
from itertools import islice

from serial import Serial
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

Stat = collections.namedtuple(
	"Stat", ["name", "mtime", "type", "size", "id", "ctime", "rev", "attrs"]
)

stat_type_map = {
	"Regular File": "file",
	"Directory": "directory",
}

try:
	O_ACCMODE = os.O_ACCMODE
except AttributeError:
	if sys.platform == "win32":
		O_ACCMODE = 3
	else:
		raise


class SerialClient(Serial):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	def write_line(self, line: str) -> None:
		self.writelines([line.encode()])

	def query_one_line(self, command: str) -> str:
		self.write_line(command)

		# TODO: Add timeout, where .readline() returns an empty string
		line = self.readline().decode("utf-8").rstrip("\n")

		return line


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

		response = self.serial.query_one_line(
			# TODO: Skip might have been seek in older versions of Linux https://stackoverflow.com/questions/2017285/how-to-extract-specific-bytes-from-a-file-using-unix#comment13831652_2017355
			# TODO: Check for command injection
			f'dd if="{self.path}" skip={offset} count={size} 2>/dev/null | base64 -w0'
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

		# TODO: Check for command injection
		# TODO: Pad with null bytes if there is a gap between the end of the file and the offset
		self.serial.write(
			f'printf "R\n"; base64 -d | dd of={self.path} bs=1 seek={offset} conv=notrunc'
		)

		# pyserial read until newline
		response = self.serial.read_until(b"R\n").decode("utf-8").rstrip("\n")

		# TODO: Check if ready signal is needed, or if .flush() is enough, or not necessary either
		if response != "R":
			# TODO: Check if this type of error is correct
			raise OSError(errno.EIO, os.strerror(errno.EIO))

		# Stream Base64
		self.serial.write(b64encode(buf))

		self.serial.write(b"\x04")  # Interrupt

		# TODO: Catch write errors, such as disk full, file not found, readonly

		# Wait for termination
		self.serial.read_until(b"\n")

		return len(response)

	def writable(self) -> bool:
		return (self.mode & O_ACCMODE) in (os.O_WRONLY, os.O_RDWR)

	def ptruncate(self, offset: int) -> int:
		if not self.writable():
			raise OSError(errno.EBADF, os.strerror(errno.EBADF))

		# If there is a gap between the end of the file and the offset, it will be filled with null bytes
		self.serial.query_one_line(f'truncate -s {offset} "{self.path}"')

		# New file size
		return offset


class _Directory(OldDirectoryProtocol):
	def __init__(self, path: Path, serial: SerialClient):
		self.path = path
		self.serial = serial

		delimiter = "\037"  # ASCII unit seperator
		suffix = "\0"  # Null terminator

		# TODO: Slightly different -c argument should be used for MacOS
		self.serial.write_line(
			f'find {path} -mindepth 1 -maxdepth 1 -exec stat -c "%n${delimiter}%s${delimiter}%F${delimiter}%Y${delimiter}%Z" "{{}}" \\; echo "{suffix}"'
		)
		contents = (
			serial.read_until(suffix.encode() + b"\n")
			.decode("utf-8")
			.rstrip("\n" + suffix)
			.splitlines()
		)

		files = []

		for item in contents:
			name, size, file_type, mtime, ctime = item.split(delimiter)

			files.append(
				Stat(
					name=name,
					mtime=datetime.fromtimestamp(int(mtime)),
					ctime=datetime.fromtimestamp(int(ctime)),
					type=stat_type_map[file_type],
					size=int(size),
					# TODO: Add id and rev?
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
		delimiter = "\037"  # ASCII unit seperator
		suffix = "\0"  # Null terminator

		# TODO: Slightly different -c argument should be used for MacOS
		response = self.serial.query_one_line(
			f'stat -c "%s${delimiter}%F${delimiter}%Y${delimiter}%Z" "{path}"'
		)
		size, file_type, mtime, ctime = response.split(delimiter)

		return NewStat(
			Stat(
				# name=None,
				mtime=datetime.fromtimestamp(int(mtime)),
				ctime=datetime.fromtimestamp(int(ctime)),
				type=stat_type_map[file_type],
				size=int(size),
				# TODO: Add id and rev?
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
		)

	def preadinto(self, handle: _File, buf: Buffer, offset: int) -> int:
		return handle.preadinto(buf, offset)

	def pwrite(self, handle: _File, data: Buffer, offset: int) -> int:
		return handle.pwrite(data, offset)

	def fsync(self, _: _File) -> None:
		# We don't need to do anything here because the serial connection always directly writes
		pass

	def _get_is_directory(self, path: Path) -> bool:
		response = self.serial.query_one_line(
			f'[ -d "{path}" ] && echo "Y" || echo "N"'
		)

		return response == "Y"

	def open_directory(self, path: Path) -> NewDirectory:
		is_directory = self._get_is_directory(path)

		if not is_directory:
			raise OSError(errno.ENOTDIR, os.strerror(errno.ENOTDIR))

		return NewDirectory(_Directory(path))

	def unlink(self, path: Path) -> None:
		self.serial.query_one_line(f'rm -f "{path}"')

	def mkdir(self, path: Path) -> None:
		self.serial.query_one_line(f'mkdir -p "{path}"')

	def rmdir(self, path: Path) -> None:
		self.serial.query_one_line(f'rm -rf "{path}"')

	def replace(self, old_path: Path, new_path: Path) -> None:
		self.serial.query_one_line(f'mv -f "{old_path}" "{new_path}"')

	def statvfs(self) -> StatVFSDC:
		response = self.serial.query_one_line('stat -f -c "%s %b %a" /')

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

		self.serial.query_one_line(
			f'touch -m -d "{new_mtime_ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")}" "{handle.path}"'
		)


def make_fs(*args, **kwargs):
	print("HI")
	return FileSystem(*args, **kwargs)


if __name__ == "__main__":
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
		on_mount=lambda _: print("HELLO"),
	)

	# serial = Serial(
	# 	port=args.port,
	# 	baudrate=args.baud_rate,
	# )
