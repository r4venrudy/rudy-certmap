"""Build versioned standard-library Go binaries; package only public project files."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
PLATFORMS = [('linux', 'amd64'), ('linux', 'arm64'), ('windows', 'amd64'), ('darwin', 'amd64'), ('darwin', 'arm64')]

def main():
    DIST.mkdir(exist_ok=True)
    if any(DIST.iterdir()):
        raise SystemExit('dist must be empty; choose a clean checkout for packaging')
    version = subprocess.check_output(['go', 'run', './cmd/certmap', '--version'], cwd=ROOT, text=True).strip().removeprefix('certmap ')
    sums = []
    for system, architecture in PLATFORMS:
        name = f'rudy-certmap-{version}-{system}-{architecture}'
        with tempfile.TemporaryDirectory(prefix='certmap-package-') as temporary:
            directory = Path(temporary) / name
            directory.mkdir()
            binary = directory / ('certmap.exe' if system == 'windows' else 'certmap')
            env = dict(os.environ, GOOS=system, GOARCH=architecture, CGO_ENABLED='0')
            subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w -buildid=', '-o', str(binary), './cmd/certmap'], cwd=ROOT, env=env, check=True)
            binary.chmod(0o755)
            for filename in ('README.md', 'LICENSE'):
                shutil.copy2(ROOT / filename, directory / filename)
            for folder in ('examples', 'docs'):
                shutil.copytree(ROOT / folder, directory / folder)
            if system == 'windows':
                archive = DIST / (name + '.zip')
                with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as package:
                    for file in sorted(directory.rglob('*')):
                        if file.is_file():
                            package.write(file, file.relative_to(directory.parent))
            else:
                archive = DIST / (name + '.tar.gz')
                with tarfile.open(archive, 'w:gz') as package:
                    package.add(directory, arcname=name)
            sums.append(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name)
            print(archive.name, flush=True)
    (DIST / 'SHA256SUMS.txt').write_text('\n'.join(sums) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
