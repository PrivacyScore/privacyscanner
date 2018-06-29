from pathlib import Path


class DirectoryFileHandler:
    def __init__(self, result_dir):
        result_dir = Path(result_dir).absolute()
        self._files_dir = result_dir / 'files'
        self._debug_files_dir = result_dir / 'debug_files'
        self._files_dir.mkdir(exist_ok=True)
        self._debug_files_dir.mkdir(exist_ok=True)

    def add_file(self, filename, contents, debug):
        output_dir = self._debug_files_dir if debug else self._files_dir
        with (output_dir / filename).open('wb') as f:
            f.write(contents)


class NoOpFileHandler:
    def add_file(self, filename, contents, debug):
        pass
