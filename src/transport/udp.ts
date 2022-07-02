import * as dgram from "dgram";
import { EventEmitter } from "events";
import { Multiaddr } from "@multiformats/multiaddr";

import { decodePacket, encodePacket, IPacket, MAX_PACKET_SIZE } from "../packet/index.js";
import { IRemoteInfo, ITransportService, TransportEventEmitter } from "./types.js";

/**
 * This class is responsible for encoding outgoing Packets and decoding incoming Packets over UDP
 */
export class UDPTransportService
  extends (EventEmitter as { new (): TransportEventEmitter })
  implements ITransportService
{
  public multiaddr: Multiaddr;
  private socket!: dgram.Socket;
  private srcId: string;

  public constructor(multiaddr: Multiaddr, srcId: string) {
    super();
    const opts = multiaddr.toOptions();
    if (opts.transport !== "udp") {
      throw new Error("Local multiaddr must use UDP");
    }
    this.multiaddr = multiaddr;
    this.srcId = srcId;
  }

  public async start(): Promise<void> {
    const opts = this.multiaddr.toOptions();
    this.socket = dgram.createSocket({
      recvBufferSize: 16 * MAX_PACKET_SIZE,
      sendBufferSize: MAX_PACKET_SIZE,
      type: opts.family === 4 ? "udp4" : "udp6",
    });
    this.socket.on("message", this.handleIncoming);
    return new Promise((resolve) => this.socket.bind(opts.port, opts.host, resolve));
  }

  public async stop(): Promise<void> {
    this.socket.off("message", this.handleIncoming);
    return new Promise((resolve) => this.socket.close(resolve));
  }

  public async send(to: Multiaddr, toId: string, packet: IPacket): Promise<void> {
    const nodeAddr = to.toOptions();
    const encodedPacket = await encodePacket(toId, packet);
    return new Promise((resolve) => this.socket.send(encodedPacket, nodeAddr.port, nodeAddr.host, () => resolve()));
  }

  public async handleIncoming(data: Buffer, rinfo: IRemoteInfo): Promise<void> {
    const multiaddr = new Multiaddr(
      `/${String(rinfo.family).endsWith("4") ? "ip4" : "ip6"}/${rinfo.address}/udp/${rinfo.port}`
    );
    try {
      const packet = await decodePacket(this.srcId, data);
      this.emit("packet", multiaddr, packet);
    } catch (e: unknown) {
      this.emit("decodeError", e as Error, multiaddr);
    }
  };
}
