export type PickedEntity = {
  pathOrUri: string;
  name: string;
};

export type TransferStatus =
  | { status: "ready"; data: string }
  | { status: "processing"; data: number }
  | { status: "completed"; data: null }
  | { status: "error"; data: string };

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
