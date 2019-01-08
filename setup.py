from setuptools import setup, find_packages

setup(
    name='privacyscanner',
    version='0.1',
    packages=find_packages(exclude=['examples', 'tests']),
    url='https://privacyscore.org/',
    license='MIT License',
    author='PrivacyScore team',
    author_email='privacyscore@informatik.uni-hamburg.de',
    description='The privacyscanner component scans websites and provides data to PrivacyScore',
    install_requires=['psycopg2-binary', 'toposort', 'dnspython', 'geoip2',
                      'requests', 'adblockeval', 'tldextract', 'pychrome',
                      'cryptography', 'pillow', 'psutil'],
    entry_points="""
    [console_scripts]
    privacyscanner=privacyscanner.scanner:main
    """
)
