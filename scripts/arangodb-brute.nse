local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Performs brute force password auditing against the ArangoDB database.
]]

---
-- @usage
-- nmap --script arangodb3-brute <ip> -p 8529
--
--
-- @output
-- PORT      STATE SERVICE
-- 8529/tcp  open  arangodb
-- | arangodb-brute:
-- |   Accounts
-- |     root:Password1 - Valid credentials
-- |   Statistics
-- |_    Performed 3542 guesses in 9 seconds, average tps: 393
--

-- **************************************************************************************************
-- **************************************************************************************************
-- FOR PURPOSES OF 4460:
-- Build nmap from this repo syntax:
--        ./configure
--        make
--        make install
--
-- This can be tested with an ec2 instance I set up with default credentials for ArangoDB
-- Instance URL: ec2-3-21-167-21.us-east-2.compute.amazonaws.com
-- Credentails on Instance: 
--        UN: web Pass: web
--        UN: user Pass: user
--
-- Test Command: nmap --script arangodb-brute ec2-3-21-167-21.us-east-2.compute.amazonaws.com -p 8529
-- 
-- **************************************************************************************************
-- **************************************************************************************************


author = "Lauren Shultz"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(8529, "arangodb3")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000

--
-- ArangoDB is setup to authenticate requests with a JWT Token
-- To get this token, you make a request to /_open/auth with the username and password
-- This can be used to test usernames and passwords if they return a token succesfully
-- ArangoDB Documentation for this: https://www.arangodb.com/docs/stable/http/general.html
-- 
arangodb_login = function(socket, username, password, host, port) 
  local body = string.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password)
  local options = { content = body }

	local res = http.generic_request(host, port, "POST", "/_open/auth", options)
  if (res.status == 200) then
    return true, "success"
  end
  return false, "err"
end

Driver = {
  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect = function( self )
    self.socket = brute.new_socket()
    local status, err = self.socket:connect(self.host, self.port)
    self.socket:set_timeout(arg_timeout)
    if(not(status)) then
      return false, brute.Error:new( "Couldn't connect to host: " .. err )
    end
    return true
  end,

  login = function (self, user, pass)
    stdnse.debug1( "Trying %s/%s ...", user, pass )
    status, response = arangodb_login( self.socket, user, pass, self.host, self.port )
    if status then
      return true, creds.Account:new( user, pass, creds.State.VALID)
    end
    return false,brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    self.socket:close()
    return true
  end
}

action = function(host, port)
  local status, result
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()
  return result
end
