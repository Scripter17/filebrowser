express=require("express");
path=require("path");
fs=require("fs");

server=express();

server.get("/*", function(req, res){
	var loc=getLocFromReq(req);
	var data={
		loc:loc,
		pathExists:pathExists(loc),
		pathIsFile:pathIsFile(loc),
		pathIsFolder:pathIsFolder(loc),
		isAbsolutePath:isAbsolutePath(loc)
	};
	res.send(data);
});

server.listen(3434);

function getLocFromReq(req){
	return req.params[0];
}
function isAbsolutePath(loc){
	//                    Windows                         Linux
	return path.sep=="\\"?/^[A-Z]:/.test(path.parse(loc)):path.isAbsolute(loc);
}
function pathExists(loc){
	try{fs.realpathSync.native(loc);}catch{return false;}
	return fs.realpathSync.native(loc)==fs.realpathSync(loc);
}
function pathIsFile(loc){
	return pathExists(loc) && !fs.lstatSync(loc).isDirectory();
}
function pathIsFolder(loc){
	return pathExists(loc) && fs.lstatSync(loc).isDirectory();
}
