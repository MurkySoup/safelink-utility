# safelink-utility
Advanced Threat Protection (ATP) Safe Links URL Encoder/Decoder Utility

# Prerequisites

This script uses the following modules:
* annotations (future)
* argparse
* sys
* typing
* urllib.parse

# Example Usage:

```
usage: safelink-utility.py [-h] [--list-formats] [-e | -d] [-u URL] [--format {barracuda,generic-a,generic-url,mimecast-domain,mimecast-url,proofpoint-v2,proofpoint-v3,safelinks}] [--prefix PREFIX]

Encode or decode protected email security URLs

options:
  -h, --help            show this help message and exit
  --list-formats        List supported encoding formats and exit
  -e, --encode
  -d, --decode
  -u URL, --url URL     URL to process
  --format {barracuda,generic-a,generic-url,mimecast-domain,mimecast-url,proofpoint-v2,proofpoint-v3,safelinks}
                        Encoding format (required for --encode)
  --prefix PREFIX       Base service URL
```

Available encoding formats:
```
  barracuda         Barracuda linkprotect (?a=)
  generic-a         Generic wrapper (?a=)
  generic-url       Generic wrapper (?url=)
  mimecast-domain   Mimecast (?domain=)
  mimecast-url      Mimecast (?url=)
  proofpoint-v2     Proofpoint URL Defense v1/v2 (u=)
  proofpoint-v3     Proofpoint URL Defense v3 (__URL__)
  safelinks         Microsoft Safe Links (?url=)
```

Decoding a safelink will auto-detect for the format and behave accordingly. Encoding requires an explicit --format selection

```
# ./safelink-utility.py --format safelinks--encode --url "https://example.com/link"

https://na01.safelinks.protection.outlook.com/?url=https%3A//example.com/link&data=04...
```

```
# ./safelink-utility.py --decode --url "https://na01.safelinks.protection.outlook.com/?url=https%3A//example.com/link&data=04..."

https://example.com/link
```

# Signalling

Standard *nix-style messaging and exit codes apply:
* Exits with code '0' for success.
* Exits with code '1' for failure.

# License

This tool is released under the Apache 2.0 license. See the LICENSE file in this repo for details.

# Built With

* [Python](https://www.python.org) designed by Guido van Rossum

# Also See:
* https://digital.va.gov/employee-resource-center/safe-link-decoder/
* https://www.microsoft.com/en-us/security/business/siem-and-xdr/microsoft-defender-office-365

## Author

**Rick Pelletier**
