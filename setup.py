from __future__ import print_function
# http://www.packtpub.com/article/writing-a-package-in-python
#from builtins import str
from future import standard_library
standard_library.install_aliases()
from setuptools import setup, Command


# adapted from Apache libcloud setup.py
class DocsCommand(Command):
    description = "generate API documentation"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import os
        import pydoc
        todo = []
        modlist = ['fgcp', 'fgcp.libcloud', 'tests']
        for curmod in modlist:
            pydoc.writedoc(curmod)
            todo.append(curmod)
            for root, dirs, files in os.walk(curmod):
                for name in files:
                    if name.startswith('__'):
                        continue
                    if not name.endswith('.py'):
                        continue
                    #modname = '%s.%s' % (curmod, name.replace('.py', ''))
                    filepath = os.path.join(root, name)
                    modname = filepath.replace('/', '.').replace('\\', '.').replace('.py', '')
                    pydoc.writedoc(modname)
                    todo.append(modname)

        import re

        # replace file:/// link with link to google code
        def clean_link(match):
            parts = match.group(1).split('/')
            file = parts.pop()
            dir = parts.pop()
            #return '"http://code.google.com/p/fgcp-client-api/source/browse/%s/%s"' % (dir, file)
            #return '"https://github.com/mikespub/fgcp-client-api/tree/master/%s/%s"' % (dir, file)
            return '"https://github.com/mikespub/fgcp-client-api/blob/master/%s/%s"' % (dir, file)
        p1 = re.compile(r'"(file:[^"]+)"')

        # replace c:\... file with local file
        def clean_file(match):
            name = match.group(1).split('\\').pop()
            return '>%s<' % name
        p2 = re.compile(r'>(\w:[^<]+)<')
        for modname in todo:
            filename = modname + '.html'
            if not os.path.exists(filename):
                continue
            print(filename)
            f = open(filename)
            lines = f.read()
            f.close()
            lines = p1.sub(clean_link, lines)
            lines = p2.sub(clean_file, lines)
            # write new file in docs
            f = open(os.path.join('docs', filename), 'w')
            f.write(lines)
            f.close()

        # get latest version of project pages
        self.get_project_pages('fgcp-client-api', ['ClientMethods', 'ResourceActions', 'APICommands', 'ClassDiagrams', 'TestServer', 'RelayServer', 'LibcloudDriver', 'REST_API'], modlist)

    def get_project_pages(self, project, wikilist, modlist):
        footerlinks = []
        #pages = {'index.html': 'http://code.google.com/p/%s/' % project}
        pages = {'index.html': 'https://github.com/mikespub/%s/wiki' % project}
        # add links to project pages
        for file in pages:
            footerlinks.append('<a href="%s">%s</a>' % (file, file.replace('.html', '')))
        wikipages = {}
        wikireplace = {}
        # define wiki pages + add links to them
        for wiki in wikilist:
            file = '%s.html' % wiki
            #url = 'http://code.google.com/p/%s/wiki/%s' % (project, wiki)
            #link = '/p/%s/wiki/%s' % (project, wiki)
            url = 'https://github.com/mikespub/%s/wiki/%s' % (project, wiki)
            link = '%s' % wiki
            wikipages[file] = url
            wikireplace[link] = file
            #wikireplace[link] = link
            #footerlinks.append('<a href="%s">%s</a>' % (file, wiki))
            footerlinks.append('<a href="%s">%s</a>' % (wiki, wiki))
        # add links to module documentation
        for mod in modlist:
            footerlinks.append('<a href="%s">pydoc %s</a>' % ('%s.html' % mod, mod))
        # build footer
        footer = '<p>Content: %s</p></body></html>' % '&nbsp;&nbsp;'.join(footerlinks)
        # get project pages
        for file in pages:
            #self.get_html(file, pages[file], '<td id="wikicontent" class="psdescription">', '</td>', wikireplace, footer)
            self.get_html(file, pages[file], '<div class="markdown-body">', '</div>', wikireplace, footer)
        # get wiki pages
        for file in wikipages:
            #self.get_html(file, wikipages[file], '<div class="vt" id="wikimaincol">', '</div>', wikireplace, footer)
            self.get_html(file, wikipages[file], '<div class="markdown-body">', '</div>', wikireplace, footer)

    def get_html(self, file, url, start_seq='<body>', end_seq='</body>', links={}, footer='<br /></body></html>'):
        print(file)
        #import urllib.request, urllib.error, urllib.parse
        import urllib.request
        f = urllib.request.urlopen(url)
        lines = f.read()
        f.close()
        # remove start_seq
        m = lines.find(start_seq)
        if m > 0:
            m += len(start_seq)
            lines = lines[m:]
        # remove end_seq
        m = lines.find(end_seq)
        if m > 0:
            lines = lines[:m]
        lines += footer
        # replace title
        import re

        def add_title(match):
            title = match.group(1)
            title = re.sub(r'<a [^>]+>.*</a>', '', title, flags=re.DOTALL)
            #return '<html><head><title>%s</title></head><body><h1>%s</h1>' % (title, title)
            return '<html><head><title>' + title + '</title></head><body><h1>' + title + '</h1>'
        lines = re.sub(r'<h1>(.+)</h1>', add_title, lines, flags=re.DOTALL)
        # replace links
        for link in links:
            lines = lines.replace(link, links[link])
        # remove wiki/* links
        lines = lines.replace('wiki/', '')
        # write new file in docs
        import os
        f = open(os.path.join('docs', file), 'w')
        f.write(lines)
        f.close()


class Pep8Command(Command):
    description = "run pep8 script"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import sys
        try:
            import pep8
            pep8
        except ImportError:
            print ('Missing "pep8" library. You can install it using pip: '
                   'pip install pep8')
            sys.exit(1)

        import os
        import subprocess
        #cwd = os.getcwd()
        cwd = '.'
        retcode = subprocess.call((r'C:\Python27\Scripts\pycodestyle --show-source --ignore=E501,E265 --filename=*.py %s/fgcp/ %s/tests/ %s/fgcp_demo.py %s/fgcp_cli.py' %
                                  (cwd, cwd, cwd, cwd)).split(' '))
        sys.exit(retcode)


f = open('README.txt')
long_description = f.read()
f.close()

setup(
    name='fgcp-client-api',
    description='Client API Library for the Fujitsu Global Cloud Platform (FGCP)',
    version='1.5.0',
    author='mikespub',
    author_email='fgcp@mikespub.net',
    packages=['fgcp'],
    install_requires=['future>=0.16.0'],
    license='Apache License 2.0',
    url='https://github.com/mikespub/fgcp-client-api',
    long_description=long_description,
    entry_points={
        'distutils.commands': [
            'docs = DocsCommand'
        ]
    },
    cmdclass={
        'docs': DocsCommand,
        'pep8': Pep8Command,
    },
    classifiers=[
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Environment :: Console',
        'Environment :: Web Environment',
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
    ]
)
