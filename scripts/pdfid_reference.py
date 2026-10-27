"""Run the reference pdfid.py on files and print normalized JSON for PDF Signal parity tests.

Usage:
    python3 -I scripts/pdfid_reference.py <path/to/pdfid.py> <file> [<file> ...]

pdfid.py is not part of this repository. Download it from the upstream project (see
README.md, "Compatibility testing") and pass its path. Each file is analysed twice, in
PDFiD's default mode and with --force, always with --extra and --all.
"""

import importlib.util
import json
import os
import sys


def load_pdfid(path):
    spec = importlib.util.spec_from_file_location('pdfid_reference_module', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def optional_float(value):
    value = value.strip()
    if value in ('', 'N/A'):
        return None
    return float(value)


def optional_int(value):
    return None if value == '' else int(value)


def analyse(pdfid, path, force):
    try:
        document = pdfid.PDFiD(path, allNames=True, extraData=True, disarm=False, force=force)
    except Exception as exception:  # pdfid.py raises some errors outside its own handler
        return {'exception': type(exception).__name__}

    attribute = document.documentElement.getAttribute
    result = {'isPdf': attribute('IsPDF') == 'True'}
    if attribute('ErrorOccured') == 'True':
        message = attribute('ErrorMessage').strip().splitlines()
        result['exception'] = message[-1].split(':')[0] if message else 'Error'
        return result
    if not result['isPdf'] and not force:
        return result

    counters = []
    for node in document.documentElement.getElementsByTagName('Keywords')[0].childNodes:
        counters.append({
            'name': node.getAttribute('Name'),
            'count': int(node.getAttribute('Count')),
            'hexcodeCount': int(node.getAttribute('HexcodeCount')),
        })
    split = next(index for index, counter in enumerate(counters) if counter['name'] == '/Colors > 2^24') + 1

    result.update({
        'header': attribute('Header'),
        'keywords': counters[:split],
        'names': counters[split:],
        'eofCount': optional_int(attribute('CountEOF')),
        'bytesAfterLastEof': optional_int(attribute('CountCharsAfterLastEOF')),
        'totalBytes': optional_int(attribute('TotalCount')),
        'totalEntropy': optional_float(attribute('TotalEntropy')),
        'streamBytes': optional_int(attribute('StreamCount')),
        'streamEntropy': optional_float(attribute('StreamEntropy')),
        'nonStreamBytes': optional_int(attribute('NonStreamCount')),
        'nonStreamEntropy': optional_float(attribute('NonStreamEntropy')),
        'dates': [
            {'value': node.getAttribute('Value'), 'name': node.getAttribute('Name')}
            for node in document.documentElement.getElementsByTagName('Dates')[0].childNodes
        ],
    })
    return result


def main(arguments):
    if len(arguments) < 2:
        sys.stderr.write(__doc__)
        return 2
    pdfid = load_pdfid(arguments[0])
    output = {'pdfidVersion': pdfid.__version__, 'python': sys.version.split()[0], 'results': {}}
    for path in arguments[1:]:
        output['results'][os.path.basename(path)] = {
            'standard': analyse(pdfid, path, False),
            'forced': analyse(pdfid, path, True),
        }
    json.dump(output, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write('\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
