function blacklisttoCloud()

htmlout = '<!DOCTYPE html>';
htmlout = [htmlout '<html><body><p>Click on the Below Link to download :<p>'];
htmlout = [htmlout '<a href="/TestDoc/BlackList.xls" download>This is the List of IPaddresses attacking the target</a>'];
htmlout = [htmlout '<p><b>Note:</b> The download attribute is not supported in Firefox, Safari or Opera version 12 (and earlier).</p>'];
htmlout = [htmlout '</body></html>'];


fid=fopen('C:\apachetomcat9\webapps\TestDoc\index.html','w');
fprintf(fid,'%s',htmlout);
fclose(fid);

end