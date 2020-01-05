#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
import threading
import time

def main():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'mysite.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)

def testrun(n):
    while (1):
        time.sleep(2)
        print("task", n)


if __name__ == '__main__':
    main()
    t = threading.Thread(target=testrun, args=("t-%s" % 1,))
    t.setDaemon(True)  # 把子进程设置为守护线程，必须在start()之前设置
    t.start()
