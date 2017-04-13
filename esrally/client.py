import gzip
import logging

import certifi
import urllib3

logger = logging.getLogger("rally.client")


class EsClientFactory:
    """
    Abstracts how the Elasticsearch client is created. Intended for testing.
    """
    def __init__(self, hosts, client_options):
        logger.info("Creating ES client connected to %s with options [%s]" % (hosts, client_options))
        self.hosts = hosts
        self.client_options = client_options

        if self._is_set(client_options, "use_ssl") and self._is_set(client_options, "verify_certs") and "ca_certs" not in client_options:
            self.client_options["ca_certs"] = certifi.where()
        if self._is_set(client_options, "basic_auth_user") and self._is_set(client_options, "basic_auth_password"):
            # Maybe we should remove these keys from the dict?
            self.client_options["http_auth"] = (client_options["basic_auth_user"], client_options["basic_auth_password"])

    def _is_set(self, client_opts, k):
        try:
            return client_opts[k]
        except KeyError:
            return False

    def create(self):
        class SmileSerializer(object):
            mimetype = 'application/smile'

            def loads(self, s):
                return s

            def dumps(self, data):
                return data

        class PoolWrap(object):
            def __init__(self, pool, compressed=False, **kwargs):
                self.pool = pool
                self.compressed = compressed

            def urlopen(self, method, url, body, retries, headers, **kw):
                if body is not None and self.compressed:
                    body = gzip.compress(body)
                return self.pool.urlopen(method, url, body=body, retries=retries, headers=headers, **kw)

            def __getattr__(self, attr_name):
                return getattr(self.pool, attr_name)

        import elasticsearch
        import time
        from elasticsearch.exceptions import ConnectionError, ConnectionTimeout, SSLError
        from urllib3.exceptions import ReadTimeoutError, SSLError as UrllibSSLError
        from urllib.parse import urlencode

        class ConfigurableHttpConnection(elasticsearch.Urllib3HttpConnection):
            def __init__(self, compressed=False, **kwargs):
                super(ConfigurableHttpConnection, self).__init__(**kwargs)
                self.headers.update({"content-type": "application/smile"})
                if compressed:
                    self.headers.update(urllib3.make_headers(accept_encoding=True))
                    self.headers.update({"Content-Encoding": "gzip"})
                self.pool = PoolWrap(self.pool, **kwargs)

            def perform_request(self, method, url, params=None, body=None, timeout=None, ignore=()):
                url = self.url_prefix + url
                if params:
                    url = '%s?%s' % (url, urlencode(params))
                full_url = self.host + url

                start = time.time()
                try:
                    kw = {}
                    if timeout:
                        kw['timeout'] = timeout

                    # in python2 we need to make sure the url and method are not
                    # unicode. Otherwise the body will be decoded into unicode too and
                    # that will fail (#133, #201).
                    if not isinstance(url, str):
                        url = url.encode('utf-8')
                    if not isinstance(method, str):
                        method = method.encode('utf-8')

                    response = self.pool.urlopen(method, url, body, retries=False, headers=self.headers, **kw)
                    duration = time.time() - start
                    # disabled for smile
                    raw_data = response.data
                    #raw_data = response.data.decode('utf-8')
                except Exception as e:
                    # set body to None to avoid logging it (it does not work for Smile)
                    self.log_request_fail(method, full_url, url, None, time.time() - start, exception=e)
                    if isinstance(e, UrllibSSLError):
                        raise SSLError('N/A', str(e), e)
                    if isinstance(e, ReadTimeoutError):
                        raise ConnectionTimeout('TIMEOUT', str(e), e)
                    raise ConnectionError('N/A', str(e), e)

                # raise errors based on http status codes, let the client handle those if needed
                if not (200 <= response.status < 300) and response.status not in ignore:
                    # set body to None to avoid logging it (it does not work for Smile)
                    self.log_request_fail(method, full_url, url, None, duration, response.status, raw_data)
                    self._raise_error(response.status, raw_data)

                # set body to None to avoid logging it (it does not work for Smile)
                self.log_request_success(method, full_url, url, None, response.status, raw_data, duration)

                return response.status, response.getheaders(), raw_data

        return elasticsearch.Elasticsearch(hosts=self.hosts,
                                           connection_class=ConfigurableHttpConnection,
                                           serializers={SmileSerializer.mimetype: SmileSerializer()},
                                           **self.client_options)

    def create_simple(self):
        import elasticsearch
        return elasticsearch.Elasticsearch(hosts=self.hosts, **self.client_options)

