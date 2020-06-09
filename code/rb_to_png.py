import os
import numpy
import scipy.misc

import array

arr_txt = [x for x in os.listdir('.') if x.endswith(".exe")]


for i in arr_txt:
	filename = i;

	f = open(filename,'rb');

	ln = os.path.getsize(filename);

	width = 256;

	rem = ln%width;

	a = array.array("B");

	a.fromfile(f,ln-rem);

	f.close();

	g = numpy.reshape(a,(len(a)/width,width));

	g = numpy.uint8(g);

	scipy.misc.imsave(i+'.png',g);