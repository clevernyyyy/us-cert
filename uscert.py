from __future__ import absolute_import
from __future__ import print_function

import argparse
import sys
import textwrap
import os.path
import re
import pandas as pd
import io

from datetime import date, datetime, timedelta

try:
  from lxml import html
  import requests
except ImportError as exception:
  print('[-] This script needs the lxml and requests library: {0}'.format(exception), file=sys.stderr)
  if sys.platform == 'win32' or sys.platform == 'cygwin':
    print("With windows, you will need to download lxml, see README.md documentation", file=sys.stderr)
  else:
    print("Install lxml with: sudo pip install lxml", file=sys.stderr)
  
  print("Install requests with: sudo pip install requests", file=sys.stderr)
  sys.exit(-1)

BASE_URL = 'https://www.us-cert.gov/ncas/bulletins/'


def get_bulletin_name(date_object=date.today()):
  '''
  return correct filename of a bulletin for a given data, published on Mondays
  '''
  while date_object.weekday():
    date_object = date_object - timedelta(days=1)
  return 'SB{0:%y}-{1:%j}'.format(date_object, date_object)

def get_bulletin_list(options):
  #
  # returns a list of all filenames of bulletins to retrieve
  #
  bulletin_list = []
  from_date = options['from_date']

  while from_date <= (options['to_date'] + timedelta(days=3)):
    bulletin_list.append(get_bulletin_name(from_date))
    from_date += timedelta(weeks=1)
  return bulletin_list

def retrieve_bulletin(filename, bulletin_name, options):
  '''
  returns a bulletin as a tree or an empty object if bulletin cannot be read
  returns bulletin via HTTP or directory file if we have it localized already
  '''
  tree = None
  url = '{0}{1}'.format(BASE_URL, bulletin_name)
  try:
    if options['force'] or not os.path.isfile(filename):
      page = requests.get(url)
      if page.status_code == 403:
        url += '-0'
        page = requests.get(url)
      if page.status_code == 200:
        tree = html.fromstring(page.text)
        if check_title(tree):
          with io.open(filename, 'wb') as html_page:
            html_page.write(page.text)
    else:
      with io.open(filename, 'r') as html_page:
        tree = html.fromstring(html_page.read())
    date_object = check_title(tree)
    if date_object and (date_object > options['from_date']) or options['latest']:
      return tree
    else:
      return None
  except requests.exceptions.ConnectionError as exception:
    sys.exit(exception.errno)

def setup_options(options):
  '''
  setup options for the rest of the program
  '''
  if not options['directory'].endswith(os.path.sep):
    options['directory'] += os.path.sep
  if not os.path.exists(options['directory']):
    os.makedirs(options['directory'])
  if not os.path.exists(options['directory']):
    os.makedirs(options['directory'])
  if not os.path.exists(options['tables']):
    os.makedirs(options['tables'])
  try:
    if options['from_date']:
      options['from_date'] = datetime.strptime(options['from_date'], '%d-%m-%Y').date()
  except ValueError:
    logging.error('Dates must be in the form dd-mm-YYYY')
    sys.exit(-1)
  options['to_date'] = date.today() + timedelta(days=2)
  options['selection'] = ['High']
  if not options['from_date'] and ('year' not in options or (options['update'])):
    options['from_date'] = date(date.today().year, 1, 1)
  else:
    if options['year'] >= 2010 and options['year'] <= date.today().year:
      options['from_date'] = date(options['year'], 1, 1)
      options['to_date'] = date(options['year'], 12, 31)
  if options['all']:
    options['from_date'] = date(2010, 1, 1)
  if options['from_date'] is None:
    options['from_date'] = options['to_date'] - timedelta(days=7)
  if options['low']:
    options['selection'].append('Low')
  if options['medium']:
    options['selection'].append('Medium')
  if options['unassigned']:
    options['selection'].append('Severity Not Yet Assigned')
  return options

def check_title(tree):
  '''
  check if tree contains vulnerability summary.
  returns a date object if successful.
  '''
  try:
    title = tree.xpath('//title/text()')[0].split(' | ')[0].replace('[\'', '')
  except AttributeError:
    title = ''

  response = re.search(r'Vulnerability Summary for the Week of (\w+\s[0-9]{1,2}\,\s[0-9]{4})', title)
  if response:
    date_object = datetime.strptime(response.group(1), '%B %d, %Y')
    return date_object.date()
  else:
    return False

def make_csv_files(tree, vuln_type, bulletin_name, options):
  '''
  takes selections and grabs html and converts to csv
  '''
  vulnerabilities = list()
  headers = ['Vendor', 'Product', 'Description', 'Published', 'CVSS', 'CVSS Score', 'Source Info']
  vendor = ''
  product = ''
  summary = 'Severity Not Yet Assigned' if vuln_type == 'Severity Not Yet Assigned' else '{0} Vulnerabilities'.format(vuln_type)

  # create vulnerability array
  for vuln in tree.xpath('//table[@summary="{0}"]/tbody/tr'.format(summary)):
    if len(vuln) > 1:
      try:
        try:
          vendor, product = vuln[0].text.split(' -- ')
        except AttributeError:
          # on occasion, US-CERT throws in random <p> tags and it screws with the parsing
          vendor, product = vuln[0][0].text.split(' -- ')
      except ValueError:
        vendor = vuln[0].text
      description = vuln[1].text
      published = vuln[2].text
      cvss = vuln[4][0].text
      try:
        cvss_score = vuln[3][0].text
      except IndexError:
        cvss_score = '0'

      source_info = build_links(vuln[4], options['link'])
      current_vuln = [vendor, product, description, published, cvss, cvss_score, source_info]
      vulnerabilities.append(current_vuln)

  df = pd.DataFrame(vulnerabilities, columns=headers)
  filename = '{0}/{1} - {2} Vulnerabilities.csv'.format(options['tables'], bulletin_name, vuln_type)
  df.to_csv(filename, index=False, encoding='utf-8')

def build_links(element, link_type):
  '''
  build links from source & patch info column
  '''
  source = ''

  if link_type == 'a':
    # loop if requesting anchor tags
    for i in range(0, len(element), 2):
      source_info_href = element[i].get("href")
      source_info_text = element[i].text
      source += '<a href="{0}" target="_blank">{1}</a><br/>'.format(source_info_href, source_info_text)
  else:
    # cannot loop as csvs do not support multiple hyperlinks (particularly excel)
    source_info_href = element[0].get("href")
    source_info_text = element[0].text
    source += '=HYPERLINK("{0}","{1}")'.format(source_info_href, source_info_text)
  return source

def parse_arguments():
  '''
  parse command line args, exits on invalid args
  '''
  parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter, 
    description=textwrap.dedent('''\
    Downloads and parses vulnerability summaries from the US-CERT website.
    Creates CSV file(s) for further dissemination.

    Copyright (C) 2017 Adam Schaal
    MIT License'''))

  parser.add_argument('-a', '--all', action='store_true', help='retrieve all missing bulletin since 2010 (lengthy!)')
  parser.add_argument('-b', '--bulletin', action='store_true', help='retrieve a specific bulletin')
  parser.add_argument('-c', '--csv', action='store_true', help='creates csv files from html')
  parser.add_argument('-d', '--directory', action='store_true', default='bulletins', help='name of directory for saving bulletins - default(bulletins)')
  parser.add_argument('-f', '--force', action='store_true', help='force download, ignore / overwrite cached directory')
  parser.add_argument('--from-date', action='store', help='starting date (dd-mm-YYYY)')
  parser.add_argument('-l', '--low', action='store_true', help='select low vulnerabilities as well')
  parser.add_argument('--latest', action='store_true', help='show latest bulletin')
  parser.add_argument('--link', action='store', help='choose "a" for anchor tags or "h" for hyperlinks - default(h)')
  parser.add_argument('-m', '--medium', action='store_true', help='show medium vulnerabilities as well')
  parser.add_argument('-t', '--tables', action='store_true', default='tables', help='name of directory for saving tables - default(tables)')
  parser.add_argument('-u', '--unassigned', action='store_true', help='show Severity Not Yet Assigned vulnerabilities as well')
  parser.add_argument('--update', action='store_true', help='retrieve all newest bulletin since last update')
  parser.add_argument('--year', action='store', nargs='?', default=0, type=int, help='retrieve all bulletins for a given year year')

  return vars(parser.parse_args())

def main():
  '''
  main loop
  '''
  options = parse_arguments()
  setup_options(options)

  for bulletin_name in get_bulletin_list(options):
    if options['bulletin']:
      bulletin_name = options['bulletin']
    filename = '{0}{1}.html'.format(options['directory'], bulletin_name)
    tree = retrieve_bulletin(filename, bulletin_name, options)
    if tree is not None and options['csv']:
      for vuln_type in options['selection']:
        make_csv_files(tree, vuln_type, bulletin_name, options)

if __name__ == "__main__":
	main()