#!/usr/bin/python
# -*- coding: utf-8 -*-
__author__ = 'Konstantin Kraynov'

import datetime as dt
import io
import logging
import pandas as pd
import requests
from bs4 import BeautifulSoup


class GVM_API(object):
    GMP = '/gmp'

    def __init__(self,
                 hostname=None,
                 port=None,
                 username=None,
                 password=None,
                 report_format_id=None,
                 verbose=True):
        self.logger = logging.getLogger('GVM_API')
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        if username is None or password is None:
            raise Exception('ERROR: Missing username or password.')

        self.username = username
        self.password = password
        self.base = 'http://{hostname}:{port}'.format(hostname=hostname, port=port)
        self.verbose = verbose
        self.processed_reports = 0
        self.report_format_id = report_format_id

        self.headers = {
            'Origin': self.base,
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.8',
            'User-Agent': 'VulnWhisperer for GVM',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Cache-Control': 'max-age=0',
            'Referer': self.base,
            'X-Requested-With': 'XMLHttpRequest',
            'Connection': 'keep-alive',
        }

        self.login()

        self.gvm_reports = self.get_reports()
        self.report_formats = self.get_report_formats()

    def login(self):
        resp = self.get_token()
        if resp.status_code == 200:
            xml_response = BeautifulSoup(resp.content, 'lxml')
            self.token = xml_response.find('token').text

            self.cookies = resp.cookies.get_dict()
        else:
            raise Exception('[FAIL] Could not login to GVM')

    def request(self, url, data=None, params=None, headers=None, cookies=None, method='POST', download=False,
                json=False):
        if headers is None:
            headers = self.headers
        if cookies is None:
            cookies = self.cookies

        timeout = 0
        success = False

        url = self.base + url
        methods = {'GET': requests.get,
                   'POST': requests.post,
                   'DELETE': requests.delete}

        while (timeout <= 10) and (not success):
            data = methods[method](url,
                                   data=data,
                                   headers=headers,
                                   params=params,
                                   cookies=cookies,
                                   verify=False)

            if data.status_code == 401:
                try:
                    self.login()
                    timeout += 1
                    self.logger.info(' Token refreshed')
                except Exception as e:
                    self.logger.error('Could not refresh token\nReason: {}'.format(str(e)))
            else:
                success = True

        if json:
            data = data.json()
        if download:
            return data.content
        return data

    def get_token(self):
        data = [
            ('cmd', 'login'),
            ('login', self.username),
            ('password', self.password),
        ]
        token = requests.post(self.base + self.GMP, data=data, verify=False)
        return token
    def get_report_formats(self):
        params = (
            ('cmd', 'get_report_formats'),
            ('token', self.token)
        )
        self.logger.info('Retrieving available report formats')
        data = self.request(url=self.GMP, method='GET', params=params)
        format_mapping = {}
        for row in BeautifulSoup(data.content, "lxml").html.body.envelope.get_report_formats.get_report_formats_response.findAll("report_format", recursive=False):
            format_mapping[row.find('name', recursive=False).contents[0]] = row.attrs['id']
        if self.verbose:
            print(format_mapping)
        return format_mapping

    def get_reports(self, complete=True):
        self.logger.info('Retreiving GVM report data...')
        params = (('cmd', 'get_reports'),
                  ('token', self.token),
                  ('ignore_pagination', 1),
                  )
        reports = self.request(self.GMP, params=params, method='GET')
        data = []

        for row in BeautifulSoup(reports.text, 'lxml').html.body.envelope.get_reports.get_reports_response\
                .findAll("report", recursive=False):
            data.append([row.find('name', recursive=False).contents[0],
                         row.report.scan_run_status.contents[0],
                         row.task.find('name', recursive=False).contents[0],
                         row.report.severity.full.contents[0],
                         row.report.result_count.hole.full.contents[0],
                         row.report.result_count.warning.full.contents[0],
                         row.report.result_count.info.full.contents[0],
                         row.report.result_count.log.full.contents[0],
                         row.report.result_count.false_positive.full.contents[0],
                         self.base + '/report/' + row.report.attrs['id'],
                         row.report.attrs['id'],
                         int(dt.datetime.strptime(row.find('name', recursive=False).contents[0], '%Y-%m-%dT%H:%M:%SZ')
                             .timestamp()),
                         row.report.severity.full.contents[0],
                         row.report.severity.full.contents[0]])
        report = pd.DataFrame(data, columns=['date', 'status', 'task', 'scan_severity', 'high', 'medium', 'low', 'log',
                                             'false_pos', 'links', 'report_ids', 'epoch', 'scan_highest_severity',
                                             'severity_rate'])
        if self.verbose:
            print(report)
        return report

    def process_report(self, report_id):
        params = (
            ('token', self.token),
            ('cmd', 'get_report'),
            ('report_id', report_id),
            ('report_format_id', '{report_format_id}'.format(report_format_id=self.report_formats['CSV Results'])),
            ('details', '1'),
        )
        self.logger.info('Retrieving {}'.format(report_id))
        req = self.request(self.GMP, params=params, method='GET')
        report_df = pd.read_csv(io.BytesIO(req.text.encode('utf-8')))
        report_df['report_ids'] = report_id
        self.processed_reports += 1
        merged_df = pd.merge(report_df, self.gvm_reports, on='report_ids').reset_index().drop('index', axis=1)
        if self.verbose:
            print(merged_df)
        return merged_df
