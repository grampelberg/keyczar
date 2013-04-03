package org.keyczar.util;

/**
 * 
 * Get the current time from the system.
 *
 */
public class SystemClock implements Clock {
  @Override
  public long now() {
    return System.currentTimeMillis();
  }
}
