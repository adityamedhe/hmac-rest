var crypto = require('crypto'),
    moment = require('moment');
    
function HmacRest(verify) {
    /* 
        This constructor takes in a verify callback to be called 
        when each authentication is done
        
        Signature: verify(username, done)
        
        The verify() function will get the password for the username,
        and invoke the done() function
    */
    
    this.verify = verify;
}

HmacRest.prototype.authenticate = function(req, res, next) {
    /*
        Express Middleware-style function
        
        1. Read request's headers (username and hash)
        2. Call the verify() to get the password from application
        3. done(username, pwd) callback will receive the same
        4. Using request params and actual db data, validate the hashes
        5. If yes, call next()
        6. Else, HTTP 401 on response
        
        Incoming HTTP Request MUST have the following headers:
        Authentication: hmac <username>:<digest>
                        (Digest = hmac sha256 hash of HTTP method + URL + Date)
        Date: <request date and time>
    */
    
    var self = this;
    
    if(!req.headers.Date || !req.headers.Authentication) {
        res.writeHeaders(400, {});
        res.write("hmac-rest: no or malformed authentication information");
        res.end();
        return;
    }
    
    var tokens = req.headers.Authentication.split(' ');
    var str_hmac = tokens[0];
    var str_authinfo = tokens[1];
    
    
    if(str_hmac !== "hmac") {
        res.writeHeaders(400, {});
        res.write("hmac-rest: malformed authentication header");
        res.end();
        return;
    }
    
    tokens = str_authinfo.split(':');
    var usernameV1 = tokens[0];
    var hashV1 = tokens[1];
    
    self.verify(usernameV1, function(err, secret) {
        if(err) {
            res.end();
        }
        const hmac = crypto.createHmac('sha256', secret);
        hmac.update(req.method+req.url+req.headers.Date);
        var hashV2 = hmac.digest();
        
        if(hashV1 === hashV2) {
            next();
        } else if(!moment().isBetween(moment(req.headers.Date), moment(req.headers.Date).add(10, 'm'))) {
            res.writeHeaders(401, {});
            res.write("hmac-rest: request outside time bounds");
            res.end();
            return;
            
        } else {
            res.writeHeaders(401, {});
            res.write("hmac-rest: authentication failed");
            res.end();
            return;
        }
    });
};

module.exports = HmacRest;