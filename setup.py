from distutils.core import setup, Extension
from os import path


d = path.abspath(path.dirname(__file__))
with open(path.join(d, 'README.rst')) as f:
    long_description = f.read()


libpycades = Extension(
    name='pycryptoprosdk.libpycades',
    sources=[
        'pycryptoprosdk/libpycades.cpp',
        'pycryptoprosdk/strings_helper.cpp',
        'pycryptoprosdk/utils.cpp',
    ],
    include_dirs=[
        'C:/Program Files (x86)/Crypto Pro/SDK/include'
    ],
    library_dirs = [ 'C:/Program Files (x86)/Crypto Pro/SDK/lib' ],
    define_macros=[
        ('WINDOWS', '1'),
        ('HAVE_LIMITS_H', '1'),
        ('HAVE_STDINT_H', '1'),
        ('SIZEOF_VOID_P', '8'),
    ],
    language='c++',
    extra_compile_args = ["/MT", "/std:c++17"]
)


setup(
    name='pycryptoprosdk',
    version='1.1.2',
    url='https://github.com/OIegZolotarev/pycryptoprosdk.git',
    author='Oleg Zolotarev, based on original work by uishnik',
    author_email='ovzolotarev@gmail.com',
    long_description=long_description,
    packages=[
        'pycryptoprosdk',
    ],
    ext_modules=[
        libpycades,
    ]
)
