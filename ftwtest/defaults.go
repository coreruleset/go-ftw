package ftwtest

/*
   # Check if there is any data and do defaults
   if self.data != '':
       # Default values for content length and header
       if 'Content-Type' not in list(headers.keys()) and stop_magic is False:
           headers['Content-Type'] = 'application/x-www-form-urlencoded'
       # check if encoded and encode if it should be
       if 'Content-Type' in list(headers.keys()):
           if headers['Content-Type'] == \
              'application/x-www-form-urlencoded' and stop_magic is False:
               if util.ensure_str(unquote(self.data)) == self.data:
                   query_string = parse_qsl(self.data)
                   if len(query_string) != 0:
                       encoded_args = urlencode(query_string)
                       self.data = encoded_args
       if 'Content-Length' not in list(headers.keys()) and stop_magic is False:
           # The two is for the trailing CRLF and the one after
           headers['Content-Length'] = len(self.data)
*/
