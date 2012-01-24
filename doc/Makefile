OUTPUTS = netlib.ps netlib.pdf

some: netlib.ps

all: $(OUTPUTS)

netlib.ps: netlib.dvi
	dvips -o $@ $<
netlib.dvi: netlib.texi
	texi2dvi $<

netlib.pdf: netlib.texi
	texi2pdf $<

