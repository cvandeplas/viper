from viper.common.abstracts import Module
from viper.core.session import __sessions__


class SurfaceAnalysis(Module):
    cmd = 'surface'
    description = 'Perform Surface Analysis'
    authors = ['Christophe Vandeplas']

    def __init__(self):
        super(SurfaceAnalysis, self).__init__()

    def run(self):
        super(SurfaceAnalysis, self).run()
        if self.args is None:
            return

        if not __sessions__.is_set():
            self.log('error', "No open session")
            return

        ####
        # Generic
        # - OK hashes (incl ssdeep)
        # - OK file size
        # - OK exif
        # - OK VT lookup
        # - OK YARA
        # - OK upload to metascan
        # - OK output of file command
        # - bit9
        # - OK string - ip/hostnames and specials
        # For EXE
        # - OK pe: peid, compiletime, language, security, sections, exports, imports
        # - send to sandbox  = REJECTED
        # - if upx: unpack and reload the file - PENDING - only if this happens often enough
        # For PDF
        # - OK pdf id
        # For DOC
        # - OK office info, ole info, vba scanner
        # For EMAIL
        # - give summary
        # - per attachment, open and iterate on each attachment

        ####
        self.log('table', dict(
            header=['Key', 'Value'],
            rows=[
                ['Name', __sessions__.current.file.name],
                ['Tags', __sessions__.current.file.tags],
                ['Size', __sessions__.current.file.size],
                ['Type', __sessions__.current.file.type],
                ['Mime', __sessions__.current.file.mime],
                ['MD5', __sessions__.current.file.md5],
                ['SHA1', __sessions__.current.file.sha1],
                ['SHA256', __sessions__.current.file.sha256],
                # ['SHA512', __sessions__.current.file.sha512],
                ['SSdeep', __sessions__.current.file.ssdeep],
                # ['CRC32', __sessions__.current.file.crc32],
                # ['Parent', __sessions__.current.file.parent],
                # ['Children', __sessions__.current.file.children]
            ]))

        self.log('', "")
        from viper.modules import virustotal
        m_vt = virustotal.VirusTotal()
        m_vt.command_line.append('-v')
        m_vt.run()
        del m_vt.command_line[:]

        self.log('', "")
        from viper.modules import metascan
        self.log('success', 'Metascan report:')
        m_m = metascan.Metascan()
        m_m.command_line.append('-v')
        m_m.run()
        del m_m.command_line[:]

        self.log('', "")
        from viper.modules import yarascan
        m_yara = yarascan.YaraScan()
        m_yara.command_line.append('scan')
        self.log('success', 'Yara:')
        m_yara.run()
        del m_yara.command_line[:]

        if __sessions__.current.file.mime == 'application/x-dosexec':
            self.log('', "")
            from viper.modules import pe
            m_pe = pe.PE()
            m_pe.command_line.append('peid')
            m_pe.run()
            del m_pe.command_line[:]

            self.log('', "")
            m_pe.command_line.append('compiletime')
            m_pe.run()
            del m_pe.command_line[:]

            self.log('', "")
            m_pe.command_line.append('language')
            m_pe.run()
            del m_pe.command_line[:]

            self.log('', "")
            m_pe.command_line.append('security')
            m_pe.command_line.append('-c')
            m_pe.run()
            del m_pe.command_line[:]

            self.log('', "")
            m_pe.command_line.append('sections')
            m_pe.run()
            del m_pe.command_line[:]

            self.log('', "")
            self.log('success', 'Header info:')
            m_pe.command_line.append('exports')
            m_pe.run()
            del m_pe.command_line[:]

            self.log('', "")
            m_pe.command_line.append('imports')
            self.log('info', "Imports:")
            m_pe.run()
            del m_pe.command_line[:]

        if __sessions__.current.file.mime == 'application/pdf':
            self.log('', "")
            self.log('success', 'PDF ID results:')
            from viper.modules import pdf
            m_pdf = pdf.PDF()
            m_pdf.command_line.append('id')
            m_pdf.run()
            del m_pdf.command_line[:]

        if __sessions__.current.file.mime in ('application/msword',   # .doc
                                              'application/msword',   # .dot
                                              'application/vnd.openxmlformats-officedocument.wordprocessingml.document',   # .docx
                                              'application/vnd.openxmlformats-officedocument.wordprocessingml.template',   # .dotx
                                              'application/vnd.ms-word.document.macroEnabled.12',   # .docm
                                              'application/vnd.ms-word.template.macroEnabled.12',   # .dotm
                                              'application/vnd.ms-excel',   # .xls
                                              'application/vnd.ms-excel',   # .xlt
                                              'application/vnd.ms-excel',   # .xla
                                              'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',   # .xlsx
                                              'application/vnd.openxmlformats-officedocument.spreadsheetml.template',   # .xltx
                                              'application/vnd.ms-excel.sheet.macroEnabled.12',   # .xlsm
                                              'application/vnd.ms-excel.template.macroEnabled.12',   # .xltm
                                              'application/vnd.ms-excel.addin.macroEnabled.12',   # .xlam
                                              'application/vnd.ms-excel.sheet.binary.macroEnabled.12',   # .xlsb
                                              'application/vnd.ms-powerpoint',   # .ppt
                                              'application/vnd.ms-powerpoint',   # .pot
                                              'application/vnd.ms-powerpoint',   # .pps
                                              'application/vnd.ms-powerpoint',   # .ppa
                                              'application/vnd.openxmlformats-officedocument.presentationml.presentation',   # .pptx
                                              'application/vnd.openxmlformats-officedocument.presentationml.template',   # .potx
                                              'application/vnd.openxmlformats-officedocument.presentationml.slideshow',   # .ppsx
                                              'application/vnd.ms-powerpoint.addin.macroEnabled.12',   # .ppam
                                              'application/vnd.ms-powerpoint.presentation.macroEnabled.12',   # .pptm
                                              'application/vnd.ms-powerpoint.template.macroEnabled.12',   # .potm
                                              'application/vnd.ms-powerpoint.slideshow.macroEnabled.12',   # .ppsm
                                              'application/vnd.ms-access',   # .mdb
                                              ):
            self.log('', "")
            self.log('success', 'Office document info:')
            from viper.modules import office
            m_office = office.Office()
            m_office.command_line.append('-m')      # Metadata - bit redundant with exif, but contains more like embedded objects
            m_office.run()
            del m_office.command_line[:]

            self.log('', "")
            from viper.modules import office
            m_office = office.Office()
            m_office.command_line.append('-o')      # OLE info
            m_office.run()
            del m_office.command_line[:]

            # self.log('', "")
            # from viper.modules import office
            # m_office = office.Office()
            # m_office.command_line.append('-s')    # document structure
            # m_office.run()
            # del m_office.command_line[:]

            self.log('', "")
            from viper.modules import office
            m_office = office.Office()
            m_office.command_line.append('-v')      # VBA Macro scanner
            m_office.run()
            del m_office.command_line[:]

        self.log('', "")
        from viper.modules import strings
        m_strings = strings.Strings()
        m_strings.command_line.append('-H')
        m_strings.command_line.append('-N')
        m_strings.command_line.append('-F')
        m_strings.command_line.append('-I')
        m_strings.run()
        del m_strings.command_line[:]

        self.log('', "")
        self.log('success', 'Exif:')
        from viper.modules import exif
        m_exif = exif.Exif()
        m_exif.run()
        del m_exif.command_line[:]



        #
        # Switch based on the file type
        # 
        # application/x-dosexec
        #rows = []
        #for key, value in metadata.items():
        #    rows.append([key, value])

        #rows = sorted(rows, key=lambda entry: entry[0])

        #self.log('info', "MetaData:")
        #self.log('table', dict(header=['Key', 'Value'], rows=rows))

