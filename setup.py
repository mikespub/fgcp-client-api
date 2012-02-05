# http://www.packtpub.com/article/writing-a-package-in-python
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
        modlist = ['fgcp', 'tests']
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
            return '"http://code.google.com/p/fgcp-client-api/source/browse/%s/%s"' % (dir, file)
        p1 = re.compile('"(file:[^"]+)"')
        # replace c:\... file with local file
        def clean_file(match):
            name = match.group(1).split('\\').pop()
            return '>%s<' % name
        p2 = re.compile('>(\w:[^<]+)<')
        for modname in todo:
            filename = modname + '.html'
            if not os.path.exists(filename):
                continue
            print filename
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
        self.get_project_pages('fgcp-client-api', ['ClientMethods', 'ResourceActions', 'APICommands', 'ClassDiagrams', 'TestServer', 'RelayServer'], modlist)

    def get_project_pages(self, project, wikilist, modlist):
        footerlinks = []
        pages = {'index.html': 'http://code.google.com/p/%s/' % project}
        # add links to project pages
        for file in pages:
            footerlinks.append('<a href="%s">%s</a>' % (file, file.replace('.html','')))
        wikipages = {}
        wikireplace = {}
        # define wiki pages + add links to them
        for wiki in wikilist:
            file = '%s.html' % wiki
            url = 'http://code.google.com/p/%s/wiki/%s' % (project, wiki)
            link = '/p/%s/wiki/%s' % (project, wiki)
            wikipages[file] = url
            wikireplace[link] = file
            footerlinks.append('<a href="%s">%s</a>' % (file, wiki))
        # add links to module documentation
        for mod in modlist:
            footerlinks.append('<a href="%s">pydoc %s</a>' % ('%s.html' % mod, mod))
        # build footer
        footer = '<p>Content: %s</p></body></html>' % '&nbsp;&nbsp;'.join(footerlinks)
        # get project pages
        for file in pages:
            self.get_html(file, pages[file], '<td id="wikicontent" class="psdescription">', '</td>', wikireplace, footer)
        # get wiki pages
        for file in wikipages:
            self.get_html(file, wikipages[file], '<div class="vt" id="wikimaincol">', '</div>', wikireplace, footer)

    def get_html(self, file, url, start_seq='<body>', end_seq='</body>', links={}, footer='<br /></body></html>'):
        print file
        import urllib2
        f = urllib2.urlopen(url)
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
            title = re.sub('<a [^>]+></a>', '', title)
            return '<html><head><title>%s</title></head><body><h1>%s</h1>' % (title, title)
        lines = re.sub('<h1>(.+)</h1>', add_title, lines)
        # replace links
        for link in links:
            lines = lines.replace(link, links[link])
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
        cwd = os.getcwd()
        retcode = subprocess.call(('pep8 --show-source --ignore=E501 --filename=*.py %s/fgcp/ %s/tests/ %s/fgcp_demo.py' %
                (cwd, cwd, cwd)).split(' '))
        sys.exit(retcode)

f = open('README.txt')
long_description = f.read()
f.close()

setup(
    name='fgcp-client-api',
    description='Client API Library for the Fujitsu Global Cloud Platform (FGCP)',
    version='1.2.2',
    author='mikespub',
    author_email='fgcp@mikespub.net',
    packages=['fgcp'],
    license='Apache License 2.0',
    url='http://code.google.com/p/fgcp-client-api/',
    long_description=long_description,
    entry_points = {
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

        'Programming Language :: Python',
    ]
)
