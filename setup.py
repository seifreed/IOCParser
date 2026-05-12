from __future__ import annotations

import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as setuptools_build_py


class CleanBuildPy(setuptools_build_py):
    def run(self) -> None:
        stale_modules = Path(self.build_lib) / "iocparser" / "modules"
        if stale_modules.exists():
            shutil.rmtree(stale_modules)
        super().run()


setup(cmdclass={"build_py": CleanBuildPy})
