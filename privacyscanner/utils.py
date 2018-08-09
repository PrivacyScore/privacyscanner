from urllib.request import urlopen


def download_file(url, fileobj):
    response = urlopen(url)
    copy_to(response, fileobj)


def copy_to(src, dest):
    while True:
        data = src.read(8192)
        if not data:
            break
        dest.write(data)