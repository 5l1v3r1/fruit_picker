import modules.robots_txt
import modules.http_headers
import modules.http_methods
import modules.access_scanner
import modules.cookie_settings
import modules.ssl_protos_and_ciphers
import sys
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-f", "--file-src", dest="url_file",
                  help="The file of urls to scan")
parser.add_option("-u", "--url", dest="url",
                  help="Single URL to scan")

(options, args) = parser.parse_args()
if options.url_file is None and options.url is None:
    print "You must set a URL or File to scan with"
    sys.exit(0)
elif options.url_file is None:
    urls = [options.url]
else:
    urls = open(options.url_file,"r")

for u in urls:
    u = u.strip()

    print "\nchecking headers - %s without ssl on port 80" % u
    t = http_headers.http_headers(u, port=80, ssl=False, verbosity=True)
    t.test()

    print "\nchecking headers - %s with ssl on port 443" % u
    t = http_headers.http_headers(u, port=443, ssl=True, verbosity=True)
    t.test()

    print "\nchecking methods - %s without ssl on port 80" % u
    t = http_methods.http_methods(u, 80, False, True)
    t.test()

    print "\nchecking methods - %s with ssl on port 443" % u
    t = http_methods.http_methods(u, 443, True, True)
    t.test()

    print "\nchecking robots - %s without ssl on port 80" % u
    t = robots_txt.robots_txt(u,80,False,True)
    r = t.test()
    if r:
            print "\nlocated robots.txt"
            f = open("robots/"+u+".txt","w")
            f.write(r)
            f.close()
    else:
            print "\nno robots.txt"

    print "\nchecking robots - %s with ssl on 443" % u
    t = robots_txt.robots_txt(u,443,True,True)
    r = t.test()
    if r:
            print "\nlocated robots.txt"
            f = open("robots/"+u+".txt","w")
            f.write(r)
            f.close()
    else:
            print "no robots.txt"

