var crypto = require('crypto'),
    moment = require('moment');

module.exports = (function(verify) {
    return function(req, res, next) {
        if(!req.headers.date || !req.headers.authentication) {
            res.writeHead(400, {});
            res.write("hmac-rest: no or malformed authentication information");
            res.end();
            return;
        }
        
        var tokens = req.headers.authentication.split(' ');
        var str_hmac = tokens[0];
        var str_authinfo = tokens[1];
        
        
        if(str_hmac !== "hmac") {
            res.writeHead(400, {});
            res.write("hmac-rest: malformed authentication header");
            res.end();
            return;
        }
        
        tokens = str_authinfo.split(':');
        var usernameV1 = tokens[0];
        var hashV1 = tokens[1];
        
        verify(usernameV1, function(err, secret) {
            if(err) {
                res.end();
            }
            const hmac = crypto.createHmac('sha256', secret);
            hmac.update(req.method+req.url+req.headers.date);
            var hashV2 = hmac.digest('hex');
            
            if(hashV1 === hashV2) {
                if(next)
                    next();
            } else {
                res.writeHead(401, {});
                res.write("hmac-rest: authentication failed");
                res.end();
                return;
            }
        });
    };
});
