from distutils.core import setup, Extension
from os import path


d = path.abspath(path.dirname(__file__))
with open(path.join(d, 'README.rst')) as f:
    long_description = f.read()


libpycades = Extension(
    name='pycryptoprosdk.libpycades',
    sources=[
        'pycryptoprosdk/libpycades.cpp',
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
    extra_compile_args = ["/MT"]
)


setup(
    name='pycryptoprosdk',
    version='1.0.1',
    url='https://github.com/Keyintegrity/pycryptoprosdk',
    author='uishnik',
    author_email='uishnik@yandex.ru',
    long_description=long_description,
    packages=[
        'pycryptoprosdk',
    ],
    ext_modules=[
        libpycades,
    ]
)
