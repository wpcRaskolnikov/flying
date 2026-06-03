export type PickedEntity = {
  pathOrUri: string;
  name: string;
};

export type TransferStatusPayload = {
  status: "Ready" | "Sending" | "Completed" | "Error";
  progress: number;
  message?: string;
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
