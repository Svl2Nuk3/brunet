/*
Copyright (C) 2008  David Wolinsky <davidiw@ufl.edu>, University of Florida

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
  
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Xml;
using System.Xml.Serialization;
using System.Security.Cryptography;
using System.Threading;

using Brunet.Concurrent;
using Brunet.Collections;
using Brunet.Connections;
using Brunet.Messaging;
using Brunet.Security;
using Brunet.Security.Dtls;
using Brunet.Security.PeerSec;
using Brunet.Security.PeerSec.Symphony;
using Brunet.Security.Transport;
using Brunet.Services;
using Brunet.Services.Coordinate;
using Brunet.Services.Dht;
using Brunet.Symphony;
using Brunet.Transport;
using Brunet.Relay;
using Brunet.Util;

namespace Brunet.Simulator {
  public class Simulator {
    public int StartingNetworkSize;
    public SortedList<Address, NodeMapping> Nodes;
    public SortedList<int, NodeMapping> TakenIDs;

    public int CurrentNetworkSize;
    protected Random _rand;
    public readonly string BrunetNamespace;

    protected bool _start;
    protected readonly double _broken;
    protected readonly bool _pathing;
    protected readonly bool _secure_edges;
    protected readonly bool _secure_senders;
    protected readonly bool _dtls;
    public bool NCEnable;
    protected RSACryptoServiceProvider _se_key;
    protected Certificate _ca_cert;
    protected readonly Parameters _parameters;

    protected readonly BroadcastHelper _bcast;

    public Simulator(Parameters parameters) : this(parameters, false)
    {
    }

    public Simulator(Parameters parameters, bool do_not_start)
    {
      _parameters = parameters;
      StartingNetworkSize = parameters.Size;
      CurrentNetworkSize = 0;
      Nodes = new SortedList<Address, NodeMapping>();
      TakenIDs = new SortedList<int, NodeMapping>();
      _bcast = new BroadcastHelper();

      if(parameters.Seed != -1) {
        Console.WriteLine(parameters.Seed);
        _rand = new Random(parameters.Seed);
      } else {
        _rand = new Random();
      }

      BrunetNamespace = "testing" + _rand.Next();
      _broken = parameters.Broken;
      _secure_edges = parameters.SecureEdges;
      _secure_senders = parameters.SecureSenders;
      _pathing = parameters.Pathing;
      _dtls = parameters.Dtls;
      if(_secure_edges || _secure_senders) {
        _se_key = new RSACryptoServiceProvider();
        byte[] blob = _se_key.ExportCspBlob(false);
        RSACryptoServiceProvider rsa_pub = new RSACryptoServiceProvider();
        rsa_pub.ImportCspBlob(blob);
        CertificateMaker cm = new CertificateMaker("United States", "UFL", 
            "ACIS", "David Wolinsky", "davidiw@ufl.edu", rsa_pub,
            "brunet:node:abcdefghijklmnopqrs");
        Certificate cert = cm.Sign(cm, _se_key);
        _ca_cert = cert;
      }

      if(parameters.LatencyMap != null) {
        SimulationEdgeListener.LatencyMap = parameters.LatencyMap;
      }

      _start = parameters.Evaluation;
      if(!do_not_start) {
        Start();
      }
      _start = false;
    }

    protected void Start()
    {
      for(int i = 0; i < _parameters.Size; i++) {
        AddNode();
      }

      if(_start) {
        for(int idx = 0; idx < Nodes.Count; idx++) {
          NodeMapping nm = Nodes.Values[idx];
          var tas = new List<TransportAddress>();
          int cidx = idx + 1;
          cidx = cidx >= Nodes.Count ? cidx - Nodes.Count : cidx;
          tas.Add(Nodes.Values[cidx].Node.LocalTAs[0]);

          cidx = idx + 2;
          cidx = cidx >= Nodes.Count ? cidx - Nodes.Count : cidx;
          tas.Add(Nodes.Values[cidx].Node.LocalTAs[0]);

          cidx = idx - 1;
          cidx = cidx >= 0 ? cidx : cidx + Nodes.Count;
          tas.Add(Nodes.Values[cidx].Node.LocalTAs[0]);

          cidx = idx - 2;
          cidx = cidx >= 0 ? cidx : cidx + Nodes.Count;
          tas.Add(Nodes.Values[cidx].Node.LocalTAs[0]);

          nm.Node.RemoteTAs = tas;
        }
        foreach(NodeMapping nm in Nodes.Values) {
          nm.Node.Connect();
        }
      }
    }

    public bool Complete()
    {
      return Complete(false);
    }

    public bool Complete(bool quiet)
    {
      DateTime start = DateTime.UtcNow;
      long ticks_end = start.AddHours(1).Ticks;
      bool success = false;
      while(DateTime.UtcNow.Ticks < ticks_end) {
        success = CheckRing(false);
        if(success) {
          break;
        }
        SimpleTimer.RunStep();
      }

      if(!quiet) {
        if(success) {
          Console.WriteLine("It took {0} to complete the ring", DateTime.UtcNow - start);
        } else {
          PrintConnections();
          PrintConnectionState();
          Console.WriteLine("Unable to complete ring.");
        }
      }

      return success;
    }

    public void AllToAll()
    {
      AllToAll(_secure_senders);
    }

    public void AllToAll(bool secure)
    {
      AllToAllHelper a2ah = new AllToAllHelper(Nodes, secure);
      a2ah.Start();
      while(a2ah.Done == 0) {
        SimpleTimer.RunStep();
      }
    }

    /// <summary>Randomly selects a node to perform broadcasting using the
    /// specified amount of forwarders.</summary>
    public void Broadcast(int forwarders)
    {
      Broadcast(_rand.Next(0, Nodes.Count), forwarders);
    }

    /// <summary>Performs a broadcast from the node at idx using the specified
    /// amount of forwarders.</summary>
    public void Broadcast(int idx, int forwarders)
    {
      _bcast.Start();
      NodeMapping nm = Nodes.Values[idx];
      BroadcastSender bs = new BroadcastSender(nm.Node as StructuredNode, forwarders);
      bs.Send(BroadcastHelper.PType);

      DateTime start = DateTime.UtcNow;
      int to_run = (int) ((_bcast.EstimatedTimeLeft - start).Ticks /
          TimeSpan.TicksPerMillisecond);

      while(to_run > 0) {
        SimpleTimer.RunSteps(to_run);
        to_run = (int) ((_bcast.EstimatedTimeLeft - DateTime.UtcNow).Ticks /
            TimeSpan.TicksPerMillisecond);
      }

      StreamWriter sw = null;
      if(_parameters.Broadcast >= -1) {
        FileStream fs = new FileStream(_parameters.Output, FileMode.Append);
        sw = new StreamWriter(fs);
      }

      int slowest = -1;
      List<int> sent_to = new List<int>();
      foreach(BroadcastReceiver br in _bcast.Results) {
        sent_to.Add(br.SentTo);
        if(sw != null) {
          sw.WriteLine(br.SentTo + ", " + br.Hops);
        }
        slowest = Math.Max(slowest, br.Hops);
      }

      if(sw != null) {
        sw.Close();
      }

      sent_to.Add(bs.SentTo);
      double avg = Average(sent_to);
      double stddev = StandardDeviation(sent_to, avg);
      Console.WriteLine("Average: {0}, StdDev: {1}", avg, stddev);
      Console.WriteLine("Hit: {0}, in: {1} ", _bcast.Results.Count, slowest);
    }

    public void Crawl()
    {
      Crawl(false, _secure_edges);
    }

    public bool Crawl(bool log, bool secure)
    {
      NodeMapping nm = Nodes.Values[0];
      SymphonySecurityOverlord bso = null;
      if(secure) {
        bso = nm.Sso;
      }

      CrawlHelper ch = new CrawlHelper(nm.Node, Nodes.Count, bso, log);
      ch.Start();
      while(ch.Done == 0) {
        SimpleTimer.RunStep();
      }

      return ch.Success;
    }

    public NodeMapping Revoke(bool log)
    {
      NodeMapping revoked = Nodes.Values[_rand.Next(0, Nodes.Count)];
      NodeMapping revoker = Nodes.Values[_rand.Next(0, Nodes.Count)];
      while(revoked != revoker) {
        revoker = Nodes.Values[_rand.Next(0, Nodes.Count)];
      }
 
      string username = revoked.Node.Address.ToString().Replace('=', '0');
      UserRevocationMessage urm = new UserRevocationMessage(_se_key, username);
      BroadcastSender bs = new BroadcastSender(revoker.Node as StructuredNode);
      bs.Send(new CopyList(BroadcastRevocationHandler.PType, urm));
      if(log) {
        Console.WriteLine("Revoked: " + revoked.Node.Address);
      }
      return revoked;
    }

    /// <summary>Remove and return the next ID from availability.</summary>
    protected int TakeID()
    {
      int id = TakenIDs.Count;
      while(TakenIDs.ContainsKey(id)) {
        id = _rand.Next(0, Int32.MaxValue);
      }
      return id;
    }

    protected AHAddress GenerateAddress()
    {
      byte[] addr = new byte[Address.MemSize];
      _rand.NextBytes(addr);
      Address.SetClass(addr, AHAddress._class);
      AHAddress ah_addr = new AHAddress(MemBlock.Reference(addr));
      if(Nodes.ContainsKey(ah_addr)) {
        ah_addr = GenerateAddress();
      }
      return ah_addr;
    }

    // Adds a node to the pool
    public virtual Node AddNode()
    {
      return AddNode(TakeID(), GenerateAddress());
    }

    public virtual Node AddNode(int id, AHAddress address)
    {
      StructuredNode node = PrepareNode(id, address);
      if(!_start) {
        node.Connect();
      }
      CurrentNetworkSize++;
      return node;
    }

    protected virtual EdgeListener CreateEdgeListener(int id)
    {
      TAAuthorizer auth = null;
      if(_broken != 0 && id > 0) {
        auth = new BrokenTAAuth(_broken);
      }

      return new SimulationEdgeListener(id, 0, auth, true);
    }

    protected virtual List<TransportAddress> GetRemoteTAs()
    {
      var RemoteTAs = new List<TransportAddress>();
      for(int i = 0; i < 5 && i < TakenIDs.Count; i++) {
        int rid = TakenIDs.Keys[_rand.Next(0, TakenIDs.Count)];
        RemoteTAs.Add(TransportAddressFactory.CreateInstance("b.s://" + rid));
      }
      if(_broken != 0) {
        RemoteTAs.Add(TransportAddressFactory.CreateInstance("b.s://" + 0));
      }

      return RemoteTAs;
    }

    protected virtual StructuredNode PrepareNode(int id, AHAddress address)
    {
      if(TakenIDs.ContainsKey(id)) {
        throw new Exception("ID already taken");
      }

      StructuredNode node = new StructuredNode(address, BrunetNamespace);

      NodeMapping nm = new NodeMapping();
      nm.ID = id;
      TakenIDs[id] = nm;
      nm.Node = node;
      Nodes.Add((Address) address, nm);

      EdgeListener el = CreateEdgeListener(nm.ID);

      if(_secure_edges || _secure_senders) {
        byte[] blob = _se_key.ExportCspBlob(true);
        RSACryptoServiceProvider rsa_copy = new RSACryptoServiceProvider();
        rsa_copy.ImportCspBlob(blob);

        string username = address.ToString().Replace('=', '0');
        CertificateMaker cm = new CertificateMaker("United States", "UFL", 
          "ACIS", username, "davidiw@ufl.edu", rsa_copy,
          address.ToString());
        Certificate cert = cm.Sign(_ca_cert, _se_key);

        CertificateHandler ch = null;
        if(_dtls) {
          ch = new OpenSslCertificateHandler();
        } else {
          ch = new CertificateHandler();
        }
        ch.AddCACertificate(_ca_cert.X509);
        ch.AddSignedCertificate(cert.X509);

        if(_dtls) {
          nm.SO = new DtlsOverlord(rsa_copy, ch, PeerSecOverlord.Security);
        } else {
          nm.Sso = new SymphonySecurityOverlord(node, rsa_copy, ch, node.Rrm);
          nm.SO = nm.Sso;
        }

        var brh = new BroadcastRevocationHandler(_ca_cert, nm.SO);
        node.GetTypeSource(BroadcastRevocationHandler.PType).Subscribe(brh, null);
        ch.AddCertificateVerification(brh);
        nm.SO.Subscribe(node, null);
        node.GetTypeSource(PeerSecOverlord.Security).Subscribe(nm.SO, null);
      }

      if(_pathing) {
        nm.PathEM = new PathELManager(el, nm.Node);
        nm.PathEM.Start();
        el = nm.PathEM.CreatePath();
        PType path_p = PType.Protocol.Pathing;
        nm.Node.DemuxHandler.GetTypeSource(path_p).Subscribe(nm.PathEM, path_p);
      }

      if(_secure_edges) {
        node.EdgeVerifyMethod = EdgeVerify.AddressInSubjectAltName;
        el = new SecureEdgeListener(el, nm.SO);
      }

      node.AddEdgeListener(el);

      if(!_start) {
        node.RemoteTAs = GetRemoteTAs();
      }

      IRelayOverlap ito = null;
      if(NCEnable) {
        nm.NCService = new NCService(node, new Point());
// My evaluations show that when this is enabled the system sucks
//        (node as StructuredNode).Sco.TargetSelector = new VivaldiTargetSelector(node, ncservice);
        ito = new NCRelayOverlap(nm.NCService);
      } else {
        ito = new SimpleRelayOverlap();
      }

      if(_broken != 0) {
        el = new Relay.RelayEdgeListener(node, ito);
        if(_secure_edges) {
          el = new SecureEdgeListener(el, nm.SO);
        }
        node.AddEdgeListener(el);
      }

      BroadcastHandler bhandler = new BroadcastHandler(node as StructuredNode);
      node.DemuxHandler.GetTypeSource(BroadcastSender.PType).Subscribe(bhandler, null);
      node.DemuxHandler.GetTypeSource(BroadcastHelper.PType).Subscribe(_bcast, null);

      // Enables Dht data store
      new TableServer(node);
      nm.Dht = new Dht(node, 3, 20);
      nm.DhtProxy = new RpcDhtProxy(nm.Dht, node);
      return node;
    }

    // removes a node from the pool
    public void RemoveNode(Node node, bool cleanly, bool output) {
      NodeMapping nm = Nodes[node.Address];
      if(output) {
        Console.WriteLine("Removing: " + nm.Node.Address);
      }
      if(cleanly) {
        node.Disconnect();
      } else {
        node.Abort();
      }
      TakenIDs.Remove(nm.ID);
      Nodes.Remove(node.Address);
      if(_pathing) {
        nm.PathEM.Stop();
      }
      CurrentNetworkSize--;
    }

    public void RemoveNode(bool cleanly, bool output) {
      int index = _rand.Next(0, Nodes.Count);
      NodeMapping nm = Nodes.Values[index];
      RemoveNode(nm.Node, cleanly, output);
    }

    /// <summary>Performs a crawl of the network using the ConnectionTable of
    /// each node.</summary>
    public bool CheckRing(bool log)
    {
      return FindMissing(log).Count == 0;
    }

    public List<AHAddress> FindMissing(bool log)
    {
      if(log) {
        Console.WriteLine("Checking ring...");
      }

      Dictionary<AHAddress, bool> found = new Dictionary<AHAddress, bool>();
      if(Nodes.Count == 0) {
        return new List<AHAddress>(0);
      }
      Address start_addr = Nodes.Keys[0];
      Address curr_addr = start_addr;
      int count = 0;

      while(count < Nodes.Count) {
        found[curr_addr as AHAddress] = true;
        Node node = Nodes[curr_addr].Node;
        ConnectionTable con_table = node.ConnectionTable;

        Connection con = null;
        try {
          con = con_table.GetLeftStructuredNeighborOf((AHAddress) curr_addr);
        } catch {
          if(log) {
            Console.WriteLine("Found no connection.");
          }
          break;
        }

        if(log) {
          Console.WriteLine("Hop {2}\t Address {0}\n\t Connection to left {1}\n", curr_addr, con, count);
        }
        Address next_addr = con.Address;

        Connection lc = null;
        try {
          Node tnode = Nodes[next_addr].Node;
          lc = tnode.ConnectionTable.GetRightStructuredNeighborOf((AHAddress) next_addr);
        } catch {}

        if( (lc == null) || !curr_addr.Equals(lc.Address)) {
          if(log) {
            if(lc != null) {
              Console.WriteLine(curr_addr + " != " + lc.Address);
            }
            Console.WriteLine("Right had edge, but left has no record of it!\n{0} != {1}", con, lc);
          }
          break;
        }
        curr_addr = next_addr;
        count++;
        if(curr_addr.Equals(start_addr)) {
          break;
        }
      }

      List<AHAddress> missing = new List<AHAddress>();
      if(count == Nodes.Count) {
        if(log) {
          Console.WriteLine("Ring properly formed!");
        }
      } else {
        foreach(AHAddress addr in Nodes.Keys) {
          if(!found.ContainsKey(addr)) {
            missing.Add(addr);
          }
        }
      }

      if(count != CurrentNetworkSize) {
        // A node must be registered, but uncreated
        missing.Add(default(AHAddress));
      }
      return missing;
    }

    /// <summary>Prints all the connections for the nodes in the simulator.</summary>
    public void PrintConnections()
    {
      foreach(NodeMapping nm in Nodes.Values) {
        Node node = nm.Node;
        PrintConnections(node);
        Console.WriteLine("==============================================================");
      }
    }

    public void PrintConnections(Node node) {
      IEnumerable ie = node.ConnectionTable.GetConnections(ConnectionType.Structured);
      Console.WriteLine("Connections for Node: " + node.Address);
      foreach(Connection c in ie) {
        Console.WriteLine(c);
      }
    }

    public void PrintConnectionState()
    {
      int count = 0;
      foreach(NodeMapping nm in Nodes.Values) {
        Node node = nm.Node;
        Console.WriteLine(node.Address + " " + node.ConState);
        count = node.IsConnected ? count + 1 : count;
      }
      Console.WriteLine("Connected: " + count);
    }

    /// <summary>Disconnects all the nodes in the simulator.</summary>
    public void Disconnect()
    {
      foreach(NodeMapping nm in Nodes.Values) {
        Node node = nm.Node;
        node.Disconnect();
      }
      Nodes.Clear();
    }

    protected class BroadcastHelper : IDataHandler {
      public static readonly PType PType = new PType("simbcast");
      public DateTime EstimatedTimeLeft { get { return _estimated_time_left; } }
      protected DateTime _estimated_time_left;

      public List<BroadcastReceiver> Results { get { return _results; } }
      protected List<BroadcastReceiver> _results;

      public void Start()
      {
        _estimated_time_left = DateTime.UtcNow.AddSeconds(1);
        _results = new List<BroadcastReceiver>();
      }

      public void HandleData(MemBlock data, ISender sender, object state)
      {
        BroadcastReceiver br = sender as BroadcastReceiver; 
        _estimated_time_left = DateTime.UtcNow.AddSeconds(1);
        _results.Add(br);
      }
    }

    /// <summary>Helps performing a live crawl on the Simulator</summary>
    protected class CrawlHelper {
      protected int _count;
      protected Hashtable _crawled;
      protected DateTime _start;
      protected Node _node;
      protected int _done;
      public int Done { get { return _done; } }
      protected int _consistency;
      protected bool _log;
      protected Address _first_left;
      protected Address _previous;
      public bool Success { get { return _crawled.Count == _count; } }
      protected SymphonySecurityOverlord _bso;

      public CrawlHelper(Node node, int count, SymphonySecurityOverlord bso, bool log) {
        _count = count;
        _node = node;
        Interlocked.Exchange(ref _done, 0);
        _crawled = new Hashtable(count);
        _log = log;
        _bso = bso;
      }

      protected void CrawlNext(Address addr) {
        bool finished = false;
        if(_log && _crawled.Count < _count) {
          Console.WriteLine("Current address: " + addr);
        }
        if(_crawled.ContainsKey(addr)) {
          finished = true;
        } else {
          _crawled.Add(addr, true);
          try {
            ISender sender = null;
            if(_bso != null) {
              sender = _bso.GetSecureSender(addr);
            } else {
              sender = new AHGreedySender(_node, addr);
            }

            Channel q = new Channel(1);
            q.CloseEvent += CrawlHandler;
            _node.Rpc.Invoke(sender, q, "sys:link.GetNeighbors");
          } catch(Exception e) {
            if(_log) {
              Console.WriteLine("Crawl failed" + e);
            }
            finished = true;
          }
        }

        if(finished) {
          Interlocked.Exchange(ref _done, 1);
          if(_log) {
            Console.WriteLine("Crawl stats: {0}/{1}", _crawled.Count, _count);
            Console.WriteLine("Consistency: {0}/{1}", _consistency, _crawled.Count);
            Console.WriteLine("Finished in: {0}", (DateTime.UtcNow - _start));
          }
        }
      }

      public void Start() {
        _start = DateTime.UtcNow;
        CrawlNext(_node.Address);
      }

      protected void CrawlHandler(object o, EventArgs ea) {
        Address addr = _node.Address;
        Channel q = (Channel) o;
        try {
          RpcResult res = (RpcResult) q.Dequeue();
          Hashtable ht = (Hashtable) res.Result;

          Address left = AddressParser.Parse((String) ht["left"]);
          Address next = AddressParser.Parse((String) ht["right"]);
          Address current = AddressParser.Parse((String) ht["self"]);
          if(left.Equals(_previous)) {
            _consistency++;
          } else if(_previous == null) {
            _first_left = left;
          }

          if(current.Equals(_first_left) && _node.Address.Equals(next)) {
            _consistency++;
          }

          _previous = current;
          addr = next;
        } catch(Exception e) {
          if(_log) {
            Console.WriteLine("Crawl failed due to exception...");
            Console.WriteLine(e);
          }
        }
        CrawlNext(addr);
      }
    }

    /// <summary>Helps performing a live AllToAll metrics on the Simulator</summary>
    protected class AllToAllHelper {
      protected long _total_latency;
      protected long _count;
      protected SortedList<Address, NodeMapping> _nodes;
      protected int _done;
      protected long _waiting_on;
      public int Done { get { return _done; } }
      protected long _start_time;
      protected object _sync;
      protected bool _secure;

      public AllToAllHelper(SortedList<Address, NodeMapping> nodes, bool secure)
      {
        _nodes = nodes;
        _count = 0;
        _total_latency = 0;
        _waiting_on = 0;
        _start_time = DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond;
        _done = 0;
        _sync = new object();
        _secure = secure;
      }

      protected void Callback(object o, EventArgs ea)
      {
        Channel q = o as Channel;
        try {
          RpcResult res = (RpcResult) q.Dequeue();
          int result = (int) res.Result;
          if(result != 0) {
            throw new Exception(res.Result.ToString());
          }

          _total_latency += (DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond) - _start_time;
        } catch {
//        } catch(Exception e) {
//          Console.WriteLine(e);
        }
        if(Interlocked.Decrement(ref _waiting_on) == 0) {
          Interlocked.Exchange(ref _done, 1);
          Console.WriteLine("Performed {0} tests on {1} nodes", _count, _nodes.Count);
          Console.WriteLine("Latency avg: {0}", _total_latency / _count);
          DateTime start = new DateTime(_start_time * TimeSpan.TicksPerMillisecond);
          Console.WriteLine("Finished in: {0}", (DateTime.UtcNow - start));
        }
      }

      public void Start() {
        foreach(NodeMapping nm_from in _nodes.Values) {
          foreach(NodeMapping nm_to in _nodes.Values) {
            if(nm_from == nm_to) {
              continue;
            }

            ISender sender = null;
            if(_secure) {
              sender = nm_from.Sso.GetSecureSender(nm_to.Node.Address);
            } else {
              sender = new AHGreedySender(nm_from.Node, nm_to.Node.Address);
            }

            Channel q = new Channel(1);
            q.CloseEvent += Callback;
            try {
              nm_from.Node.Rpc.Invoke(sender, q, "sys:link.Ping", 0);
              _count++;
              _waiting_on++;
            } catch {
//            } catch(Exception e) {
//              Console.WriteLine(e);
            }
          }
        }
      }
    }

    /// <summary>Used to perform a DhtPut from a specific node.</summary>
    protected class DhtPut {
      public bool Done { get { return _done; } }
      protected bool _done;
      protected readonly Node _node;
      protected readonly MemBlock _key;
      protected readonly MemBlock _value;
      protected readonly int _ttl;
      protected readonly EventHandler _callback;
      public bool Successful { get { return _successful; } }
      protected bool _successful;

      public DhtPut(Node node, MemBlock key, MemBlock value, int ttl, EventHandler callback)
      {
        _node = node;
        _key = key;
        _value = value;
        _ttl = ttl;
        _callback = callback;
        _successful = false;
      }

      public void Start()
      {
        Channel returns = new Channel();
        returns.CloseEvent += delegate(object o, EventArgs ea) {
          try {
            _successful = (bool) returns.Dequeue();
          } catch {
          }

          _done = true;
          if(_callback != null) {
            _callback(this, EventArgs.Empty);
          }
        };
        Dht dht = new Dht(_node, 3, 20);
        dht.AsyncPut(_key, _value, _ttl, returns);
      }
    }

    /// <summary>Used to perform a DhtGet from a specific node.</summary>
    protected class DhtGet {
      public bool Done { get { return _done; } }
      protected bool _done;
      public Queue<MemBlock> Results;
      public readonly Node Node;
      protected readonly MemBlock _key;
      protected readonly EventHandler _enqueue;
      protected readonly EventHandler _close;

      public DhtGet(Node node, MemBlock key, EventHandler enqueue, EventHandler close)
      {
        Node = node;
        _key = key;
        _enqueue = enqueue;
        _close = close;
        Results = new Queue<MemBlock>();
      }

      public void Start()
      {
        Channel returns = new Channel();
        returns.EnqueueEvent += delegate(object o, EventArgs ea) {
          while(returns.Count > 0) {
            Hashtable result = null;
            try {
              result = returns.Dequeue() as Hashtable;
            } catch {
              continue;
            }

            byte[] res = result["value"] as byte[];
            if(res != null) {
              Results.Enqueue(MemBlock.Reference(res));
            }
          }
          if(_enqueue != null) {
            _enqueue(this, EventArgs.Empty);
          }
        };

        returns.CloseEvent += delegate(object o, EventArgs ea) {
          if(_close != null) {
            _close(this, EventArgs.Empty);
          }
          _done = true;
        };

        Dht dht = new Dht(Node, 3, 20);
        dht.AsyncGet(_key, returns);
      }
    }

    /// <summary>Calculates the average of a data set.</summary>
    public static double Average(List<int> data)
    {
      long total = 0;
      foreach(int point in data) {
        total += point;
      }

      return (double) total / data.Count;
    }

    /// <summary>Calculates the standard deviation given a data set and the
    /// average.</summary>
    public static double StandardDeviation(List<int> data, double avg)
    {
      double variance = 0;
      foreach(int point in data) {
        variance += Math.Pow(point - avg, 2.0);
      }

      return Math.Sqrt(variance / (data.Count - 1));
    }

  }

  public class NodeMapping {
    public IDht Dht;
    public RpcDhtProxy DhtProxy;
    public int ID;
    public NCService NCService;
    public Node Node;
    public PathELManager PathEM;
    public SecurityOverlord SO;
    public SymphonySecurityOverlord Sso;
  }

  /// <summary> Randomly breaks all edges to remote entity.</summary>
  public class BrokenTAAuth : TAAuthorizer {
    double _prob;
    Hashtable _allowed;
    Random _rand;

    public BrokenTAAuth(double probability) {
      _prob = probability;
      _allowed = new Hashtable();
      _rand = new Random();
    }

    public override TAAuthorizer.Decision Authorize(TransportAddress a) {
      int id = ((SimulationTransportAddress) a).ID;
      if(id == 0) {
        return TAAuthorizer.Decision.Allow;
      }

      if(!_allowed.Contains(id)) {
        if(_rand.NextDouble() > _prob) {
          _allowed[id] = TAAuthorizer.Decision.Allow;
        } else {
          _allowed[id] = TAAuthorizer.Decision.Deny;
        }
      }

      return (TAAuthorizer.Decision) _allowed[id];
    }
  }
}
