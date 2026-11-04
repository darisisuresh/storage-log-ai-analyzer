"""Build the static browser application with the same Python analysis engine."""
from pathlib import Path
import importlib.metadata
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'dist' / 'web'


def build():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for source in (ROOT / 'web').iterdir():
        if source.is_file():
            shutil.copy2(source, OUTPUT / source.name)
    with zipfile.ZipFile(OUTPUT / 'engine.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
        for source in sorted((ROOT / 'src' / 'storage_log_analyzer').glob('*.py')):
            archive.write(source, 'storage_log_analyzer/' + source.name)
        for name in ('ijson', 'tzdata'):
            distribution = importlib.metadata.distribution(name)
            for file in sorted(distribution.files or []):
                if str(file).startswith(name + '/') and not str(file).endswith(('.pyc', '.so', '.pyd')):
                    archive.write(distribution.locate_file(file), str(file))
            for file in distribution.files or []:
                if any(part.lower().startswith(('license', 'copying')) for part in file.parts):
                    archive.write(distribution.locate_file(file), 'licenses/' + str(file))
        archive.write(ROOT / 'LICENSE', 'licenses/storage-log-analyzer-LICENSE')
    shutil.copy2(ROOT / 'samples' / 'mixed-storage.log', OUTPUT / 'sample.log')
    print(f'Browser application built in {OUTPUT}')


if __name__ == '__main__':
    build()
