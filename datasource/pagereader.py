from osnma.navdata import InavPage
from datasource.sbf.sbfparser import SbfBlockFactory, GalRawINavBlock

class PageReader:
    @staticmethod
    def from_string(string, source):
        """Create a PageReader from the specification string.

        :string: String specifying the type of the reader
        :source: the source from which the data is read from
        :returns: PageReader subclass for reading the specified data

        """
        if string == 'ascii':
            return AsciiPageReader(source)
        return SbfPageReader(source)

    def read(self):
        '''Read a Galileo INAV page from some source. Abstract.
        '''
        pass

class SbfPageReader(PageReader):
    """Read SBF files and construct InavPage object from the GalRawInav blocks."""
    def __init__(self, source):
        self.source = source
        self.bf = SbfBlockFactory(source)
        self.bf.registerBlock(GalRawINavBlock)

    def read(self):
        """Read an SBF GalRawInavBlock and convert it to InavPage, which is
        returned.

        :returns: InavPage with the equivalent data, and arrival_dt

        """
        block, arrival_dt = self.bf.read()
        page = block.to_inav_page()
        return page, arrival_dt

class AsciiPageReader(PageReader):
    """Class for producing InavPages from ASCII input. Format is expected to be
    ASCII lines with format: svid, wn, tow, navigation_page_in_hex
    The delimiter can be set, and the file descriptor 'fd' can be anything with
    the method 'readline'. Therefore it can be for example an open file
    descriptor (opened with 'open') or 'sys.stdin'.
    """
    def __init__(self, fd, delimiter=" "):
        self.fd = fd
        self.delimiter = delimiter

        # We mostly use the "SBF-format" where the 6 zero-bits between the even
        # and odd page are removed. Septentrio for example gives the pages
        # already in this format so they do not need to be removed. In case
        # your navigation bits have length 240, set this to yes.
        self.remove_middle_6_bits = False

    def read(self):
        """Read the next line from the input
        :returns: InavSubframe

        """
        line = self.fd.readline()

        # EOF
        if not line:
            return None

        t = line.rstrip().split(self.delimiter)
        svid = int(t[0])
        wn = int(t[1])
        tow = int(t[2])
        page = BitArray(hex=t[3])

        navbits = BitArray()
        if self.remove_middle_6_bits:
            evenpage = page[:114]
            oddpage = page[120:]
            navbits.append(evenpage)
            navbits.append(oddpage)
        else:
            navbits = page

        return InavPage(wn, tow, svid, navbits)
