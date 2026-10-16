import { EventEmitter } from "node:events";

import { sanitizeActivityEvent } from "./contracts.mjs";

const DEFAULT_LIMIT = 64;

export class ActivityStore extends EventEmitter {
  #events = [];
  #sequence = 0;
  #limit;

  constructor(options = {}) {
    super();
    const limit = options.limit ?? DEFAULT_LIMIT;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 512) {
      throw new Error("activity limit must be an integer from 1 through 512");
    }
    this.#limit = limit;
    this.setMaxListeners(128);
  }

  append(value, at = new Date()) {
    const event = sanitizeActivityEvent(value, this.#sequence + 1, at);
    if (!event) return null;
    this.#sequence = event.sequence;
    this.#events.push(event);
    if (this.#events.length > this.#limit) this.#events.splice(0, this.#events.length - this.#limit);
    this.emit("event", event);
    return event;
  }

  since(sequence = 0) {
    const after = Number.isSafeInteger(sequence) && sequence >= 0 ? sequence : 0;
    return Object.freeze(this.#events.filter((event) => event.sequence > after));
  }

  latestSequence() {
    return this.#sequence;
  }
}

export const activityStoreInternals = Object.freeze({ DEFAULT_LIMIT });
