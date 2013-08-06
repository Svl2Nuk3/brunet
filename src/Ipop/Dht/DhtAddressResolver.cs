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

using Brunet;
using Brunet.Applications;
using Brunet.Collections;
using Brunet.Concurrent;
using Brunet.Services.Dht;
using Brunet.Util;

using System;
using System.Text;
using System.Collections;
using System.Collections.Generic;
using System.Net.Sockets;

namespace Ipop.Dht {
  /// <summary>This class provides a method to do address resolution over the
  /// Brunet Dht, where entries are listed in the dht by means of the 
  /// DhtDHCPServer.</summary>
  public class DhtAddressResolver: IAddressResolver {
    public event MappingDelegate MissedMapping;
    /// <summary>Clean up the cache entries every 10 minutes.</summary>
    public const int CLEANUP_TIME_MS = 600000;
    /// <summary>Cache based upon Dht and thus verified</summary>
    protected readonly TimeBasedCache<MemBlock, Address> _verified_cache;
    /// <summary>Cache based upon check calls</summary>
    protected readonly TimeBasedCache<MemBlock, Address> _incoming_cache;
    /// <summary>A lock synchronizer for the hashtables and cache.</summary>
    protected readonly Object _sync = new Object();
    /// <summary>Failed query attempts.</summary>
    protected readonly Dictionary<MemBlock, int> _attempts;
    /// <summary>Contains which IP Address Misses are pending.</summary>
    protected readonly Dictionary<MemBlock, bool> _queued;
    /// <summary>Maps the Channel in MissCallback to an IP.</summary>
    protected readonly Dictionary<Channel, MemBlock> _mapping;
    /// <summary>The dht object to use for dht interactions.</summary>
    protected readonly IDht _dht;
    /// <summary>The ipop namespace where the dhcp server is storing names</summary>
    protected readonly string _ipop_namespace;

    /// <summary>Creates a DhtAddressResolver Object.</summary>
    /// <param name="dht">The dht object to use for dht interactions.</param>
    /// <param name="ipop_namespace">The ipop namespace where the dhcp server
    /// is storing names.</param>
    public DhtAddressResolver(IDht dht, string ipop_namespace)
    {
      _dht = dht;
      _ipop_namespace = ipop_namespace;
      _verified_cache = new TimeBasedCache<MemBlock, Address>(CLEANUP_TIME_MS);
      _incoming_cache = new TimeBasedCache<MemBlock, Address>(CLEANUP_TIME_MS);
      _attempts = new Dictionary<MemBlock, int>();
      _queued = new Dictionary<MemBlock, bool>();
      _mapping = new Dictionary<Channel, MemBlock>();
    }

    /// <summary>Translates an IP Address to a Brunet Address.  If it is in the
    /// cache it returns a result, otherwise it returns null and begins a Miss
    /// lookup.</summary>
    /// <param name="ip">The IP Address to translate.</param>
    /// <returns>Null if none exists or there is a miss or the Brunet Address if
    /// one exists in the cache</returns>
    public Address Resolve(MemBlock ip)
    {
      Address stored_addr;
      bool update;

      bool contains = _verified_cache.TryGetValue(ip, out stored_addr, out update);
      if(!contains) {
        contains = _incoming_cache.TryGetValue(ip, out stored_addr, out update);
        update = true;
      }

      if(contains) {
        _incoming_cache.Update(ip, stored_addr);
      }

      if(update) {
        Miss(ip);
      }
      return stored_addr;
    }

    /// <summary>Is the right person sending me this packet?</summary>
    /// <param name="ip">The IP source.</param>
    /// <param name="addr">The Brunet.Address source.</summary>
    public bool Check(MemBlock ip, Address addr)
    {
      Address stored_addr = Resolve(ip);

      if(stored_addr != null) {
        if(addr.Equals(stored_addr)) {
          return true;
        } else{
          throw new AddressResolutionException(String.Format(
                "IP:Address mismatch, expected: {0}, got: {1}",
                addr, stored_addr), AddressResolutionException.Issues.Mismatch);
        }
      }

      // No mapping, so use the given mapping
      _incoming_cache.Update(ip, addr);
      return true;
    }

    /// <summary>This is called if the cache's don't have an Address mapping.
    /// It prepares an asynchronous Dht query if one doesn't already exist,
    /// that is only one query at a time per IP regardless of how many misses
    /// occur.  The ansychonorous call back is call MissCallback.</summary>
    /// <param name="ip">The IP Address to look up in the Dht.</param>
    protected bool Miss(MemBlock ip)
    {
      Channel queue = null;

      lock(_sync) {
        // Already looking up or found
        if(_queued.ContainsKey(ip)) {
          return false;
        }

        int count = 1;
        if(_attempts.ContainsKey(ip)) {
          count =  _attempts[ip] + 1;
        }
        _attempts[ip] = count;

        if(count >= 3) {
          _attempts.Remove(ip);
          throw new AddressResolutionException("No Address mapped to: " + Utils.MemBlockToString(ip, '.'),
              AddressResolutionException.Issues.DoesNotExist);
        }

        _queued[ip] = true;
        queue = new Channel(1);
        queue.CloseEvent += MissCallback;
        _mapping[queue] = ip;
      }

      String ips = Utils.MemBlockToString(ip, '.');
      ProtocolLog.WriteIf(IpopLog.ResolverLog, String.Format( "Adding {0} to queue.", ips));

      byte[] key = Encoding.UTF8.GetBytes("dhcp:" + _ipop_namespace + ":" + ips);
      try {
        _dht.AsyncGet(key, queue);
      } catch {
        queue.CloseEvent -= MissCallback;
        lock(_sync) {
          _queued.Remove(ip);
          _mapping.Remove(queue);
        }
        queue.Close();
      }

      return true;
    }

    /// <summary>This is the asynchronous callback for Miss.  This contains the
    /// lookup results from the Dht.  If there is a valid mapping it is added to
    /// the cache.  Either way, new queries can now be run for the IP address
    /// after the completion of this method.</summary>
    /// <param name="o">Contains the Channel where the results are stored.</param>
    /// <param name="args">Null.</param>
    protected void MissCallback(Object o, EventArgs args)
    {
      Channel queue = (Channel) o;
      // Requires synchronized reading
      MemBlock ip = null;
      lock(_sync) {
        ip = _mapping[queue];
      }
      String ips = Utils.MemBlockToString(ip, '.');
      Address addr = null;

      try {
        Hashtable dgr = (Hashtable) queue.Dequeue();
        addr = AddressParser.Parse(Encoding.UTF8.GetString((byte[]) dgr["value"]));
        if(IpopLog.ResolverLog.Enabled) {
          ProtocolLog.Write(IpopLog.ResolverLog, String.Format(
            "Got result for {0} ::: {1}.", ips, addr));
        }
      } catch {
        if(IpopLog.ResolverLog.Enabled) {
          ProtocolLog.Write(IpopLog.ResolverLog, String.Format(
            "Failed for {0}.", Utils.MemBlockToString(ip, '.')));
        }
      }

      lock(_sync) {
        if(addr != null) {
          _verified_cache.Update(ip, addr);
          _attempts.Remove(ip);
        }

        _queued.Remove(ip);
        _mapping.Remove(queue);
      }

      if (addr == null) {
        var handler = MissedMapping;
        if(handler != null) {
          if(_incoming_cache.TryGetValue(ip, out addr)) {
            handler(ips, addr);
          }
        }
      }
    }

    /// <summary>Stops the timer at which point a new DhtAddressResolver
    /// will need to be constructed, if used in the same process.</summary>
    public void Stop()
    {
      _verified_cache.Stop();
    }
  }
}
