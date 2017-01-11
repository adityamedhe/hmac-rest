var crypto = require('crypto'),
    moment = require('moment');

module.exports = (function(verify, failureResponse) {
    return function(req, res, next) {
        if(!req.headers.hmacdate || !req.headers.authentication) {
            res.writeHead(400, {});
            failureResponse.auth_error = "hmac-rest: no or malformed authentication information";
            res.write(JSON.stringify(failureResponse));
            res.end();
            return;
        }
        
        var tokens = req.headers.authentication.split(' ');
        var str_hmac = tokens[0];
        var str_authinfo = tokens[1];
        
        
        if(str_hmac !== "hmac") {
            res.writeHead(400, {});
            failureResponse.auth_error = "hmac-rest: malformed authentication information";
            res.write(JSON.stringify(failureResponse));
            res.end();
            return;
        }
        
        tokens = str_authinfo.split(':');
        var usernameV1 = tokens[0];
        var hashV1 = tokens[1];
        
        verify(usernameV1, function(err, response) {
            if(err) {
                res.end();
            }
            const hmac = crypto.createHmac('sha256', response.secret);
            hmac.update(req.method.toLowerCase()+req.url.split('?')[0]+req.headers.hmacdate);
            var hashV2 = hmac.digest('hex');
            if(hashV1 === hashV2) {
                if(next)
                    next();
            } else {
                res.writeHead(401, {});
                failureResponse.auth_error = "hmac-rest: authentication failed";
                res.write(JSON.stringify(failureResponse));
                res.end();
                return;
            }
        });
    };
});
