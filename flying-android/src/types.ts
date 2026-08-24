export type PickedEntity = {
  pathOrUri: string;
  name: string;
};

export type TransferStatus = "ready" | "processing" | "completed" | "error";

export type TransferStatusPayload = {
  status: TransferStatus;
  data: number | string | { peerId?: string } | null;
  peerId?: string;
};

type ConnectConfig = {
  mode: "connect";
  connectIp: string;
};

type ListenConfig = {
  mode: "listen";
};

type RelayListenConfig = {
  mode: "relay_listen";
  relayAddr: string;
  peerId: string;
};

type RelayDialConfig = {
  mode: "relay_dial";
  relayAddr: string;
  remotePeerId: string;
};

export type ConnectionConfig =
  | ConnectConfig
  | ListenConfig
  | RelayListenConfig
  | RelayDialConfig;
