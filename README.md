# safelink-utility
Advanced Threat Protection (ATP) Safe Links URL Encoder/Decoder Utility

# Prerequisites

This script uses the following modules:
* sys
* re
* urllib.parse
* argparse

# Example Usage:

```
usage: safelink-utility.py [-h] (-e | -d) --url URL

options:
  -h, --help         show this help message and exit
  -e, --encode
  -d, --decode
  --url URL, -u URL
```

```
# ./safelink-utility.py --encode --url "https://example.com/link"

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
