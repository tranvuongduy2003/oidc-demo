export type Notice = {
  tone: 'progress' | 'success' | 'error'
  text: string
}

export type ApiResult =
  | { tone: 'neutral'; text: string }
  | { tone: 'success'; text: string; details: string }
  | { tone: 'error'; text: string }
