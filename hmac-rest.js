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
        1. Read request's headers (username and hash)
        2. Call the verify() to get the password from application
        3. done(username, pwd) callback will receive the same
        4. Using request params and actual db data, validate the hashes
        5. If yes, call next()
        6. Else, HTTP 401 on response
        
        Incoming HTTP Request MUST have the following headers:
        Authentication: hmac <username>:<password>:<digest>
        Date: <request date and time>
    */
};