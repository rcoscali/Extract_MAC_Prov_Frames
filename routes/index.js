var os = require('os');
var express = require('express');
var router = express.Router();
var mime = require('mime');
var reader = require ("buffered-reader");
var formidable = require('formidable');
var path = require('path');
var fs = require('fs');
const bodyParser = require("body-parser");
const sqlite3 = require('sqlite3').verbose();
const {exec} = require("child_process");
const form = formidable({uploadDir: os.tmpdir()});
var app = require('../app');

const DbLogPath = process.env.MAC_PROV_ROOT + '/var/log';
const DbDirPath = process.env.MAC_PROV_ROOT + '/var/lib';
const DbFilePath = DbDirPath + '/keystore.db';

// Instanciate keystore DB
var keystoredb =
    new sqlite3.Database(
        DbFilePath,
        sqlite3.OPEN_READWRITE | sqlite3.OPEN_FULLMUTEX | sqlite3.OPEN_PRIVATECACHE,
        (err) =>
        {
            if (err)
            {
                console.error(err.message);
                process.exit(1);
            }
            else
            {
                console.log('****** Keys DB openned, accepting requests !');

                var app = express();

                /* GET home page. */
                router.get(
                    '/',
                    (req, res, next) =>
                    {
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);
                                        var renderParams =
                                            {
                                                title: 'MAC Prov Tool',
                                                help: 'Tools for manipulating MAC keys, MAC provisionning CAN frames and SHE commands for Key provisionning from log files ',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 0
                                            }
                                        res.render(
                                            'index',
                                            renderParams
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* GET set mac keys. */
                router.get(
                    '/:kMacEcu/:kMasterEcu',
                    function(req, res, next)
                    {
                        var kMacEcu = req.params['kMacEcu'];
                        var kMasterEcu = req.params['kMasterEcu'];
                        console.log("K_MAC_ECU = " + kMacEcu);
                        console.log("K_MASTER_ECU = " + kMasterEcu);
                        keystoredb.serialize(
                            () =>
                            {
                                keystoredb.run(
                                    "UPDATE MACKeys SET IsActive = 0 WHERE IsMaster = 0 AND MacKey != '?'",
                                    [kMacEcu]
                                );
                                keystoredb.run(
                                    "UPDATE MACKeys SET IsActive = 0 WHERE IsMaster = 1 AND MacKey != '?'",
                                    [kMasterEcu]
                                );
                                keystoredb.run(
                                    "INSERT INTO MACKeys (MacKey, IsMaster, IsActive) VALUE (?, 0, 1)",
                                    [kMacEcu],
                                );
                                keystoredb.run(
                                    "INSERT INTO MACKeys (MacKey, IsMaster, IsActive) VALUE (?, 1, 1)",
                                    [kMasterEcu],
                                );                              
                            }
                        );
                        res.render(
                            'index',
                            {
                                title: 'MAC Prov Tool',
                                help: 'Tools for manipulating MAC keys, MAC provisionning CAN frames and SHE commands for Key provisionning from log files ',
                                accordionTab: 0
                            }
                        );                                      
                    }
                );
                
                /*
                 * Log Files functions
                 */
                
                /* GET import_log_file. */
                router.get(
                    '/import_log_file',
                    (req, res, next) =>
                    {
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);
                                        res.render(
                                            'import_log_file',
                                            {
                                                title: 'Import a log file',
                                                help: 'Import a log file and store it in DB',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 0
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );

                /* POST upload_log_file */
                router.post(
                    '/upload_log_file',
                    async (req, res, next) =>
                    {
                        var releve, result;
                        try
                        {
                            var activeKeys = new Object;
                            var k_mac_ecu = "Not Set !";
                            var k_master_ecu = "Not Set !";
                            keystoredb.get(
                                "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                                (err, row) =>
                                {
                                    if (row != undefined)
                                    {
                                        console.log("Active K_MAC_ECU = " + row.MacKey);
                                        k_mac_ecu = row.MacKey;
                                    }
                                    keystoredb.get(
                                        "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                        (err, row) =>
                                        {
                                            if (row != undefined)
                                            {
                                                console.log("Active K_MASTER_ECU = " + row.MacKey);
                                                k_master_ecu = row.MacKey;
                                            }
                                            activeKeys['kMacEcu'] = k_mac_ecu;
                                            activeKeys['kMasterEcu'] = k_master_ecu;
                                            console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                            console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);
                                            form.parse(
                                                req,
                                                (err, fields, files) =>
                                                {
                                                    if (err)
                                                    {
                                                        next(err);
                                                        return;
                                                    }
                                                    req.fields = fields;
                                                    req.files = files;
                                                    
                                                    var log_file = req.files.log_file;
                                                    console.log("Uploaded '" + log_file.originalFilename + "' file to: " + log_file.filepath);
                                                    fs.readFile(
                                                        log_file.filepath,
                                                        'utf8',
                                                        (err, data) =>
                                                        {
                                                            // First let's write file in DB repository
                                                            var targetFilePath = DbLogPath + "/" + log_file.originalFilename;
                                                            console.log("Target file path: " + targetFilePath);
                                                            var newTargetFilePath = targetFilePath;
                                                            var fileCntr = 0;
                                                            var extension = path.extname(newTargetFilePath);
                                                            var name = path.basename(newTargetFilePath, extension);
                                                            while (fs.existsSync(newTargetFilePath))
                                                            {
                                                                console.log("Target file path exists: " + newTargetFilePath);
                                                                fileCntr++;
                                                                newTargetFilePath =  DbLogPath + "/" + name + '_' + fileCntr + extension;
                                                            }
                                                            console.log("Found free target file path : " + newTargetFilePath);
                                                            fs.rename(
                                                                log_file.filepath,
                                                                newTargetFilePath,
                                                                function (err)
                                                                {
                                                                    if (err)
                                                                    {
                                                                        console.log("Couldn't rename file " + log_file.filepath + " !");
                                                                        next(err);
                                                                        return;
                                                                    }
                                                                    console.log('File Renamed to ' + newTargetFilePath + '!');
                                                                    const importDateRE = /^date (?<date>.*)$/;
                                                                    const uuidRE = /^\/\/ Measurement UUID: (?<uuid>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$/;
                                                                    const versionRE = /^\/\/ version (?<version>[0-9.]+)$/;
                                                                    var lines = data.toString().split(/\r?\n/);
                                                                    console.log('File has ' + lines.length + ' lines !');
                                                                    var dateLine = lines.filter(elem => elem.match(importDateRE));
                                                                    console.log("Date line: " + dateLine)
                                                                    var uuidLine = lines.filter(elem => elem.match(uuidRE));
                                                                    console.log("UUID line: " + uuidLine)
                                                                    var versionLine = lines.filter(elem => elem.match(versionRE));
                                                                    console.log("Version line: " + versionLine)
                                                                    var logdate, uuid, version;
                                                                    dateLine.map(
                                                                        (line) =>
                                                                        {
                                                                            var fields = importDateRE.exec(line);
                                                                            logdate = fields.groups.date;
                                                                            console.log("    Log Date = " + logdate);
                                                                        }
                                                                    );
                                                                    uuidLine.map(
                                                                        (line) =>
                                                                        {
                                                                            var fields = uuidRE.exec(line);
                                                                            uuid = fields.groups.uuid;
                                                                            console.log("    UUID = " + uuid);
                                                                        }
                                                                    );
                                                                    versionLine.map(
                                                                        (line) =>
                                                                        {
                                                                            var fields = versionRE.exec(line);
                                                                            version = fields.groups.version;
                                                                            console.log("    Version = " + version);
                                                                        }
                                                                    );
                                                                    keystoredb.run(
                                                                        "INSERT INTO LogFiles (Name, LogDate, ImportDate, Version, Size, LinesNb, UUID, Content)   \
                                                                                VALUES        (   ?,       ?,          ?,       ?,    ?,       ?,    ?,       ?);",
                                                                        [
                                                                            path.basename(newTargetFilePath),
                                                                            logdate,
                                                                            (new Date()).toString(),
                                                                            version,
                                                                            log_file.size,
                                                                            lines.length,
                                                                            uuid, 
                                                                            data
                                                                        ],
                                                                        (err) =>
                                                                        {
                                                                            if (err)
                                                                            {
                                                                                console.log("Error while adding log file record in DB!");
                                                                                next(err);
                                                                                return;
                                                                            }
                                                                            res.render(
                                                                                'upload_log_files',
                                                                                {
                                                                                    title: 'Upload a log file',
                                                                                    help: 'Upload, process and store a log file and its parameters for further MAC Prov frames extraction',
                                                                                    content: 'File ' + log_file.originalFilename + ' uploaded successfully !',
                                                                                    activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                                                    accordionTab: 0
                                                                                }
                                                                            );
                                                                        }
                                                                    );
                                                                }
                                                            );
                                                        }
                                                    );
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        }
                        catch(err)
                        {
                            next(err);
                            return;
                        }
                    }
                );
                
                /* GET list_log_file. */
                router.get(
                    '/list_log_files',
                    (req, res, next) =>
                    {
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);
                                        var stmt = "SELECT id, Name, LogDate, ImportDate, Version, Size, LinesNb, UUID, FramesExtracted FROM LogFiles";
                                        keystoredb.all(
                                            stmt,
                                            [],
                                            (err, rows) =>
                                            {
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                var renderParams =
                                                    {
                                                        title: 'List stored log files',
                                                        help: 'List all log files imported and stored locally in DB',
                                                        logfiles: {},
                                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                        accordionTab: 0
                                                    };
                                                var contentHtml = "";
                                                var firstRow = true;
                                                var lastRow = false;
                                                var index = 0;
                                                rows.forEach(
                                                    (row) =>
                                                    {
                                                        firstRow = (index == 0);
                                                        lastRow = (index == rows.length -1);
                                                        contentHtml +=
                                                            (firstRow ? "[" : "")+"{id:"+row.id+","+
                                                            "Name:'"+row.Name+"',"+
                                                            "LogDate:'"+row.LogDate.replace("'", "\'")+"',"+
                                                            "ImportDate:'"+row.ImportDate.replace("'", "\'")+"',"+
                                                            "Version:'"+row.Version+"',"+
                                                            "Size:"+row.Size+","+
                                                            "LinesNb:"+row.LinesNb+","+
                                                            "UUID:'"+row.UUID+"',"+
                                                            "FramesExtracted:"+(row.FramesExtracted ? "true" : "false")+"}"+(lastRow ? "]" : ",");
                                                        index++;
                                                    }
                                                );
                                                renderParams['logfiles'] = contentHtml;
                                                res.render(
                                                    'list_log_files',
                                                    renderParams
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* GET delete_log_files. */
                router.get(
                    '/delete_log_files',
                    (req, res, next) =>
                    {
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);
                                        keystoredb.run(
                                            "DELETE FROM LogFiles",
                                            []
                                        );
                                        fs.readdir(
                                            DbLogPath,
                                            (err, files) =>
                                            {
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                
                                                for (const file of files)
                                                {
                                                    fs.unlink(
                                                        path.join(DbLogPath, file),
                                                        (err) =>
                                                        {
                                                            if (err)
                                                            {
                                                                next(err);
                                                                return;
                                                            }
                                                        }
                                                    );
                                                }
                                            }
                                        );
                                        res.render(
                                            'delete_log_files',
                                            {
                                                title: 'Delete stored log files',
                                                help: 'Delete LOG files stored in DB (record & files)',
                                                content: 'All Log files where removed !', 
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 0
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* GET extract_mac_frames. */
                router.get(
                    '/extract_mac_frames/:logFileId',
                    (req, res, next) =>
                    {
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);

                                        // Select log file with id :logFileId with FramesExtracted flag being false
                                        var stmt = "SELECT id, Name, UUID, Content FROM LogFiles WHERE FramesExtracted='0' AND id = ?";
                                        keystoredb.get(
                                            stmt,
                                            [req.params[logFileId]],
                                            (err, row) =>
                                            {
                                                // Examples of logging entries in log files
                                                //
                                                //   19.232049 CANFD   1 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 10 44 31 01 02 53 00 00   106156  135   303000 c80016cf 4ba00150 4b280150 20002776 2000091c
                                                // 8.191 1 7C3             Rx   d 8 02 10 03 00 00 00 00 00
                                                //   7.157965 CANFD   2 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 02 3e 00 55 55 55 55 55   104657  132   323000 a800f7a3 4ba00150 4b280150 20002776 2000091c
                                                //   0.007142 CANFD   1 Rx        192  ADAS_A10C_FD                     1 0 8  8 00 00 50 04 7f ff 00 10   103656  136   303000 980150f4 4ba00150 4b280150 20002776 2000091c
                                                //   0.002801 CANFD   1 Rx        25e  ADASISv2_A101_FD                 1 0 8  8 00 00 00 00 00 00 00 00   105156  139   303000 f800b73d 4ba00150 4b280150 20002776 2000091c
                                                //   
                                                var result_log = "";
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                // Initialization of parameters for rendering the page
                                                var renderParams =
                                                    {
                                                        title: 'Extract MAC Prov frames',
                                                        help: 'Extract MAC Prov frames from a selected log file in DB',
                                                        logfiles: {},
                                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                        accordionTab: 1
                                                    };
                                                var index = 0;

                                                // For the found log file 
                                                var lines = row.Content.toString().split(/\r?\n/);
                                                console.log('==============================================================');
                                                console.log('File \'' + row.Name + '\' has ' + lines.length + ' lines !');
                                                result_log += "==============================================================\\n";
                                                result_log += "File '" + row.Name + "' has " + lines.length + " lines !\\n";
                                                var provFrameRE  = /^ ? ?(?<Timestamp>[0-9.]*) (?<ProvRE>([A-Z]+)? *[12]? ?Rx *[0-9a-zA-Z]+  (?<Name>DTOOL_to_[A-Za-z0-9_]+)) +[0-9] [0-9] [a-zA-Z0-9] *(?<Data>[ 0-9a-zA-Z]+31 01 02 53[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$/;
                                                var provFramesStart = new Array;
                                                for (var i = 0; i < lines.length; i++)
                                                {
                                                    var fields;
                                                    if ((fields = provFrameRE.exec(lines[i])))
                                                    {
                                                        result_log += "Found provisionning frame starting at line #" + i + "\\n";
                                                        var provRE = new RegExp('^ ? ?(?<Timestamp>[0-9.]*) ' + fields.groups.ProvRE + ' +[0-9] [0-9] [a-zA-Z0-9]  *(?<Data>[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$');
                                                        provFramesStart.push({index:i,regex:provRE});
                                                    }
                                                }
                                                
                                                var provFrames = new Array;
                                                var ix = 0;
                                                provFramesStart.map(
                                                    (provStart) =>
                                                    {
                                                        // Frame part index
                                                        var fix = 0;
                                                        provFrames[ix] = new Object;
                                                        provFrames[ix]['Parts'] = new Array;
                                                        var payload = "";
                                                        
                                                        console.log("Extracting frame  #" + ix + " at line #" + provStart['index'] + " with RE: /" + provStart['regex']);
                                                        result_log += "Extracting frame #" + ix + " at line #" + provStart['index'] + " with RE: /" + provStart['regex'] + "\\n";
                                                        
                                                        for (var i = provStart['index']; i < lines.length; i++, fix++)
                                                        {
                                                            var fields;
                                                            // If match
                                                            if (fields = provStart['regex'].exec(lines[i]))
                                                            {
                                                                result_log += "Adding payload for frame #" + ix + " from line #" + i + ": ";
                                                                provFrames[ix]['Parts'][fix] = new Object;
                                                                provFrames[ix]['Parts'][fix]['Timestamp'] = fields.groups.Timestamp;
                                                                result_log += "Timestamp='" + provFrames[ix]['Parts'][fix]['Timestamp'] + "' ";
                                                                var localpayload = fields.groups.Data;
                                                                provFrames[ix]['Parts'][fix]['Data'] = localpayload;
                                                                result_log += "Data='" + provFrames[ix]['Parts'][fix]['Data'] + "' ";
                                                                // The first frame payload contains UDS addressing
                                                                if (i == provStart['index'])
                                                                    provFrames[ix]['Parts'][fix]['Payload'] = localpayload.replace(/ /g, "").substring(13, localpayload.length);
                                                                else
                                                                    provFrames[ix]['Parts'][fix]['Payload'] = localpayload.replace(/ /g, "").substring(3, localpayload.length);
                                                                result_log += "Payload='" + provFrames[ix]['Parts'][fix]['Payload'] + "' ";
                                                                provFrames[ix]['Parts'][fix]['Tail'] = fields.groups.Tail;
                                                                result_log += "Tail='" + provFrames[ix]['Parts'][fix]['Tail'] + "'\\n";
                                                                if (provFrames[ix]['Parts'][fix]['Payload'].startsWith("010055"))
                                                                {
                                                                    if (payload.length > 128)
                                                                        payload = payload.substring(0, 128);
                                                                    break;
                                                                }
                                                                payload += provFrames[ix]['Parts'][fix]['Payload'];
                                                            }
                                                        }
                                                        provFrames[ix]['Payload'] = payload;
                                                        console.log("Frame #" + ix + " payload = '" + provFrames[ix]['Payload'] + "'");
                                                        result_log += "Frame #" + ix + " payload = '" + provFrames[ix]['Payload'] + "'\\n";
                                                        ix++;
                                                        
                                                        // Update database by setting FramesExtracted flag to true
                                                        provFrames.map(
                                                            (provFrame) =>
                                                            {
                                                                var updateStmt = "UPDATE LogFiles SET FramesExtracted='1' WHERE LogFiles.Name=?";
                                                                keystoredb.run(
                                                                    updateStmt,
                                                                    [row.Name],
                                                                    (err) =>
                                                                    {
                                                                        if (err)
                                                                        {
                                                                            next(err);
                                                                            return;
                                                                        }
                                                                        var insertStmt = "INSERT INTO MACProvFrames (LogFileId, Frame) \
                                                                                                         VALUES             (        ?,     ?);";
                                                                        keystoredb.run(
                                                                            insertStmt,
                                                                            [row.id, provFrame['Payload']],
                                                                            (err) =>
                                                                            {
                                                                                if (err)
                                                                                {
                                                                                    next(err);
                                                                                    return;
                                                                                }
                                                                            }
                                                                        );
                                                                    }
                                                                );
                                                            }
                                                        );
                                                    }
                                                );
                                            }
                                        );
                                        renderParams['result_log'] = result_log;
                                        res.render(
                                            'extract_mac_frames',
                                            renderParams
                                        );
                                    }
                                );
                            }
                        );
                    }
                );

                /* GET extract_mac_frames. */
                router.get(
                    '/extract_mac_frames',
                    (req, res, next) =>
                    {
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);

                                        // Select all log files with FramesExtracted flag being false
                                        var stmt = "SELECT id, Name, UUID, Content FROM LogFiles WHERE FramesExtracted='0'";
                                        keystoredb.all(
                                            stmt,
                                            [],
                                            (err, rows) =>
                                            {
                                                // Examples of logging entries in log file
                                                //
                                                //   19.232049 CANFD   1 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 10 44 31 01 02 53 00 00   106156  135   303000 c80016cf 4ba00150 4b280150 20002776 2000091c
                                                // 8.191 1 7C3             Rx   d 8 02 10 03 00 00 00 00 00
                                                //   7.157965 CANFD   2 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 02 3e 00 55 55 55 55 55   104657  132   323000 a800f7a3 4ba00150 4b280150 20002776 2000091c
                                                //   0.007142 CANFD   1 Rx        192  ADAS_A10C_FD                     1 0 8  8 00 00 50 04 7f ff 00 10   103656  136   303000 980150f4 4ba00150 4b280150 20002776 2000091c
                                                //   0.002801 CANFD   1 Rx        25e  ADASISv2_A101_FD                 1 0 8  8 00 00 00 00 00 00 00 00   105156  139   303000 f800b73d 4ba00150 4b280150 20002776 2000091c
                                                //   
                                                var result_log = "";
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                // Initialization of parameters for rendering the page
                                                var renderParams =
                                                    {
                                                        title: 'Extract MAC Prov frames',
                                                        help: 'Extract MAC Prov frames from a selected log file in DB',
                                                        logfiles: {},
                                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                        accordionTab: 1
                                                    };
                                                var index = 0;
                                                // For each log file found
                                                rows.forEach(
                                                    (row) =>
                                                    {
                                                        var lines = row.Content.toString().split(/\r?\n/);
                                                        console.log('==============================================================');
                                                        console.log('File \'' + row.Name + '\' has ' + lines.length + ' lines !');
                                                        result_log += "==============================================================\\n";
                                                        result_log += "File '" + row.Name + "' has " + lines.length + " lines !\\n";
                                                        var provFrameRE  = /^ ? ?(?<Timestamp>[0-9.]*) (?<ProvRE>([A-Z]+)? *[12]? ?Rx *[0-9a-zA-Z]+  (?<Name>DTOOL_to_[A-Za-z0-9_]+)) +[0-9] [0-9] [a-zA-Z0-9] *(?<Data>[ 0-9a-zA-Z]+31 01 02 53[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$/;
                                                        var provFramesStart = new Array;
                                                        for (var i = 0; i < lines.length; i++)
                                                        {
                                                            var fields;
                                                            if ((fields = provFrameRE.exec(lines[i])))
                                                            {
                                                                result_log += "Found provisionning frame starting at line #" + i + "\\n";
                                                                var provRE = new RegExp('^ ? ?(?<Timestamp>[0-9.]*) ' + fields.groups.ProvRE + ' +[0-9] [0-9] [a-zA-Z0-9]  *(?<Data>[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$');
                                                                provFramesStart.push({index:i,regex:provRE});
                                                            }
                                                        }
                                                        
                                                        var provFrames = new Array;
                                                        var ix = 0;
                                                        provFramesStart.map(
                                                            (provStart) =>
                                                            {
                                                                // Frame part index
                                                                var fix = 0;
                                                                provFrames[ix] = new Object;
                                                                provFrames[ix]['Parts'] = new Array;
                                                                var payload = "";
                                                                
                                                                console.log("Extracting frame  #" + ix + " at line #" + provStart['index'] + " with RE: /" + provStart['regex']);
                                                                result_log += "Extracting frame #" + ix + " at line #" + provStart['index'] + " with RE: /" + provStart['regex'] + "\\n";
                                                                
                                                                for (var i = provStart['index']; i < lines.length; i++, fix++)
                                                                {
                                                                    var fields;
                                                                    // If match
                                                                    if (fields = provStart['regex'].exec(lines[i]))
                                                                    {
                                                                        result_log += "Adding payload for frame #" + ix + " from line #" + i + ": ";
                                                                        provFrames[ix]['Parts'][fix] = new Object;
                                                                        provFrames[ix]['Parts'][fix]['Timestamp'] = fields.groups.Timestamp;
                                                                        result_log += "Timestamp='" + provFrames[ix]['Parts'][fix]['Timestamp'] + "' ";
                                                                        var localpayload = fields.groups.Data;
                                                                        provFrames[ix]['Parts'][fix]['Data'] = localpayload;
                                                                        result_log += "Data='" + provFrames[ix]['Parts'][fix]['Data'] + "' ";
                                                                        // The first frame payload contains UDS addressing
                                                                        if (i == provStart['index'])
                                                                            provFrames[ix]['Parts'][fix]['Payload'] = localpayload.replace(/ /g, "").substring(13, localpayload.length);
                                                                        else
                                                                            provFrames[ix]['Parts'][fix]['Payload'] = localpayload.replace(/ /g, "").substring(3, localpayload.length);
                                                                        result_log += "Payload='" + provFrames[ix]['Parts'][fix]['Payload'] + "' ";
                                                                        provFrames[ix]['Parts'][fix]['Tail'] = fields.groups.Tail;
                                                                        result_log += "Tail='" + provFrames[ix]['Parts'][fix]['Tail'] + "'\\n";
                                                                        if (provFrames[ix]['Parts'][fix]['Payload'].startsWith("010055"))
                                                                        {
                                                                            if (payload.length > 128)
                                                                                payload = payload.substring(0, 128);
                                                                            break;
                                                                        }
                                                                        payload += provFrames[ix]['Parts'][fix]['Payload'];
                                                                    }
                                                                }
                                                                provFrames[ix]['Payload'] = payload;
                                                                console.log("Frame #" + ix + " payload = '" + provFrames[ix]['Payload'] + "'");
                                                                result_log += "Frame #" + ix + " payload = '" + provFrames[ix]['Payload'] + "'\\n";
                                                                ix++;
                                                                
                                                                // Update database by setting FramesExtracted flag to true
                                                                provFrames.map(
                                                                    (provFrame) =>
                                                                    {
                                                                        var updateStmt = "UPDATE LogFiles SET FramesExtracted='1' WHERE LogFiles.Name=?";
                                                                        keystoredb.run(
                                                                            updateStmt,
                                                                            [row.Name],
                                                                            (err) =>
                                                                            {
                                                                                if (err)
                                                                                {
                                                                                    next(err);
                                                                                    return;
                                                                                }
                                                                                var insertStmt = "INSERT INTO MACProvFrames (LogFileId, Frame) \
                                                                                                         VALUES             (        ?,     ?);";
                                                                                keystoredb.run(
                                                                                    insertStmt,
                                                                                    [row.id, provFrame['Payload']],
                                                                                    (err) =>
                                                                                    {
                                                                                        if (err)
                                                                                        {
                                                                                            next(err);
                                                                                            return;
                                                                                        }
                                                                                    }
                                                                                );
                                                                            }
                                                                        );
                                                                    }
                                                                );
                                                            }
                                                        );
                                                    }
                                                );
                                                renderParams['result_log'] = result_log;
                                                res.render(
                                                    'extract_mac_frames',
                                                    renderParams
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* GET list_mac_prov_frame. */
                router.get(
                    '/list_mac_prov_frame/:logFileId',
                    (req, res, next) =>
                    {
			console.log("/list_mac_prov_frame/:logFileId");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);

                                        var stmt = "SELECT DISTINCT l.id, l.Name, f.Frame, f.SHECmdExtracted \
                                                    FROM LogFiles l \
                                                                    LEFT JOIN MACProvFrames f ON l.id = f.LogFileId \
                                                    WHERE length(f.Frame) > 0 AND l.id = ?";
                                        keystoredb.all(
                                            stmt,
                                            [req.params['logFileId']],
                                            (err, rows) =>
                                            {
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                var renderParams =
                                                    {
                                                        title: 'List MAC Provisionning frames',
                                                        help: 'List MAC provisionning frames extracted',
                                                        macprovframes: '',
                                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                        accordionTab: 1
                                                    };
                                                var contentHtml = "";
                                                var ix = 0;
                                                rows.forEach(
                                                    (row) =>
                                                    {
                                                        if (ix != 0)
                                                            contentHtml += ",";
                                                        contentHtml +=
							    "{id:" + row.id + "," +
							    "{name:'" + row.Name + "'," +
							    "frame:'" + row.Frame + "'," +
							    "sheCmdExtracted:" + (row.SHECmdExtracted ? "true" : "false") + "}";
                                                        ix++;
                                                    }
                                                );
                                                renderParams['macprovframes'] = "[" + contentHtml + "]";
                                                res.render(
                                                    'list_mac_prov_frame',
                                                    renderParams
                                                );                              
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* GET list_mac_prov_frame. */
                router.get(
                    '/list_mac_prov_frame',
                    (req, res, next) =>
                    {
			console.log("/list_mac_prov_frame/");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 0",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    console.log("Active K_MAC_ECU = " + row.MacKey);
                                    k_mac_ecu = row.MacKey;
                                }
                                keystoredb.get(
                                    "SELECT MacKey FROM MACKeys WHERE IsActive = 1 AND IsMaster = 1",
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            console.log("Active K_MASTER_ECU = " + row.MacKey);
                                            k_master_ecu = row.MacKey;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        console.log("renderParams.activeKeys['kMacEcu'] = " + activeKeys['kMacEcu']);
                                        console.log("renderParams.activeKeys['kMasterEcu'] = " + activeKeys['kMasterEcu']);

                                        var stmt = "SELECT DISTINCT l.id, l.Name, f.Frame, f.SHECmdExtracted \
                                                    FROM LogFiles l \
                                                                  LEFT JOIN MACProvFrames f ON l.id = f.LogFileId \
                                                    WHERE length(f.Frame) > 0";
                                        keystoredb.all(
                                            stmt,
                                            [],
                                            (err, rows) =>
                                            {
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                var renderParams =
                                                    {
                                                        title: 'List MAC Provisionning frames',
                                                        help: 'List MAC provisionning frames extracted',
                                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                        macprovframes: '',
                                                        accordionTab: 1
                                                    };

                                                var contentHtml = "";
                                                var ix = 0;
                                                rows.forEach(
                                                    (row) =>
                                                    {
                                                        if (ix != 0)
                                                            contentHtml += ",";
                                                        contentHtml +=
							    "{id:" + row.id + "," +
							    "name:'" + row.Name + "'," +
							    "frame:'" + row.Frame + "'," +
							    "sheCmdExtracted:" + (row.SHECmdExtracted ? "true" : "false") + "}";
                                                        ix++;
                                                    }
                                                );
                                                renderParams['macprovframes'] = "[" + contentHtml + "]";
                                                res.render(
                                                    'list_mac_prov_frame',
                                                    renderParams
                                                );                              
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );

                /* GET list_she_args_packets. */
                router.get(
                    '/extract_she_args_packets/:frameId',
                    (req, res, next) =>
                    {
                        res.render(
                            'extract_she_args_packets',
                            {
                                title: 'Extract SHE args packets',
                                help: 'Extract SHE args packets from MAC prov frames',
                                accordionTab: 2
                            }
                        );
                    }
                );
                
                /* GET list_she_args_packets. */
                router.get(
                    '/extract_she_args_packets',
                    (req, res, next) =>
                    {
                        res.render(
                            'extract_she_args_packets',
                            {
                                title: 'Extract SHE args packets',
                                help: 'Extract SHE args packets from MAC prov frames',
                                accordionTab: 2
                            }
                        );
                    }
                );
                
                /* GET list_she_args_packets. */
                router.get('/list_she_args_packets', function(req, res, next) {
                    res.render('list_she_args_packets',
                               {
                                   title: 'List stored SHE args packets',
                                   help: '',
                                   accordionTab: 2
                               });
                });
                
                /* GET unwrap_mac_keys. */
                router.get('/unwrap_mac_keys', function(req, res, next) {
                    res.render('unwrap_mac_keys',
                               {
                                   title: 'Unwrap MAC keys provided in a selected SHE args packets',
                                   help: '',
                                   accordionTab: 2
                               });
                });

                /* GET set_mac_keys. */
                router.get(
                    '/set_mac_keys',
                    (req, res, next) =>
                    {
                        res.render(
                            'set_mac_keys',
                            {
                                title: 'Set MAC keys',
                                help: 'Set active K_MAC_ECU and K_MASTER_ECU',
                                accordionTab: 2
                            }
                        );
                    }
                );
            }
        }
    );
        
module.exports = router;
