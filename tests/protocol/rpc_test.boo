#!/usr/bin/env booi

#Run this with booi -ducky -r:Brunet.dll rpc_test.boo

import Brunet
import System
import System.Security.Cryptography

#Make the RpcManager to deal with our requests
def make_rpc(node as Node, port as int, remote as string):
  node.AddEdgeListener( UdpEdgeListener(port) )
  node.RemoteTAs.Add( TransportAddressFactory.CreateInstance( remote ) )
  rpc = RpcManager( ReqrepManager.GetInstance(node) )
  node.Connect();
  return rpc

#Here is the test class which provides some methods
class test_handler:
  def sayhello(name as string):
    return "Hello: ${name}";
  def sum(a as int, b as int):
    return a+b
  def concat(bunch as System.Collections.IList):
    result = ""
    for i in bunch:
      result = result + i.ToString()
    return result

print "Welcome to BooRpcTest"
port = Int32.Parse(prompt("What port to listen on?"))
ta = prompt("What remote ta?")
addr = AHAddress( RNGCryptoServiceProvider() )
print addr
mynode = StructuredNode( addr )
myrpc = make_rpc(mynode, port, ta)

#Lets provide a method to run:

helloer = test_handler()

myrpc.AddHandler("test", helloer);

while true:
  addr = AddressParser.Parse( prompt("What node?") );
  quit = ""
  vals = []
  while quit != "quit":
    quit = prompt("Next value..")
    vals.Add( quit )
  q = BlockingQueue() 
  myrpc.Invoke(AHSender(mynode, addr), q, "test.concat",vals);
  res = q.Dequeue() as RpcResult
  try:
    print res.Result;
  except x:
    print x
