# us-cert.py

This script helps convert US-CERT notifications into readable CSV files.  It also aggregates the HTML into a named directory structure.


### Dependencies

`lxml`, `requests`, `pandas`

### Installation


##### Linux / OSX
`pip install -r requirements.txt`

##### Windows
I think you need to download `lxml` separately.



### Example usage

```

python uscert.py -csl --from-date 20-09-2017

```


### Flags

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

