# us-cert.py

This script helps convert US-CERT notifications into readable CSV files.  It also aggregates the HTML into a named directory structure.


### Dependencies

`lxml`, `requests`, `pandas`

### Installation


##### Linux / OSX
`pip install -r requirements.txt`

##### Windows
* Download `lxml` from pypi(https://pypi.python.org/pypi/lxml/3.6.4).
* This also worked for `lxml`:  `set STATICBUILD=true && pip install lxml`
* `sudo pip install pandas`  (if you get an error try `sudo pip install --upgrade pip` first)


### Example usage

Getting the highs, mediums, lows and unassigned severity alerts into csv tables from September 20th, 2017 to current date.

```
python uscert.py -clum --from-date 20-09-2017
```


### Usage

```
usage: uscert.py [-h] [-a] [-b BULLETIN] [-c] [-d DIRECTORY] [-f]
                 [--from-date FROM_DATE] [-l] [--latest] [-m] [-t TABLES] [-u]
                 [--year [YEAR]]

Donwloads and parses vulnerability summaries from the US-CERT website.
Creates CSV file(s) for further dissemination.

Copyright (C) 2017 Adam Schaal
MIT License

optional arguments:
  -h, --help            show this help message and exit
  -a, --all             retrieve all missing bulletin since 2010 (!)
  -b BULLETIN, --bulletin BULLETIN
                        retrieve a specific bulletin
  -c, --csv             creates csv files from html
  -d DIRECTORY, --directory DIRECTORY
                        name of directory for saving bulletins
  -f, --force           force download, ignore / overwrite cached directory
  --from-date FROM_DATE
                        starting date (dd-mm-YYYY)
  -l, --low             select low vulnerabilities as well
  --latest              show latest bulletin
  -m, --medium          show medium vulnerabilities as well
  -t TABLES, --tables TABLES
                        name of directory for saving tables
  -u, --unassigned      show Severity Not Yet Assigned vulnerabilities as well
  --year [YEAR]         retrieve all bulletins for a given year year
```


### Inspiration from
https://github.com/PeterMosmans/vulnerability-alerter

