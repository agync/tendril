package dev.tendril;

/**
 * The host proved it knows this device and refused it. A subclass of {@link
 * IllegalStateException}, so existing catches keep working.
 *
 * <p>App guidance:
 *
 * <ul>
 *   <li>{@link Reason#REVOKED}: the host blocks this device key permanently. Re-pairing needs a new
 *       device identity, so offer to forget the host.
 *   <li>{@link Reason#PENDING}: the host has not confirmed this device yet. Retry with backoff.
 *   <li>{@link Reason#OTHER}: a refusal with a close code in 4400 to 4499.
 * </ul>
 *
 * <p>A host sends at most one notice per peer in a short window and answers the rest as an unknown
 * peer, so a revoked device can see one refusal and a generic failure on a rapid retry.
 */
public final class TendrilRefusedException extends IllegalStateException {
  private static final long serialVersionUID = 1L;

  /** Close code of a host that refuses a revoked peer. */
  public static final int CLOSE_PEER_REVOKED = 4001;

  /** Close code of a host that refuses a peer it has not confirmed. */
  public static final int CLOSE_PEER_PENDING = 4004;

  public enum Reason {
    REVOKED("revoked", "refused_revoked"),
    PENDING("pending", "refused_pending"),
    OTHER("other", "refused");

    private final String wire;
    private final String code;

    Reason(String wire, String code) {
      this.wire = wire;
      this.code = code;
    }

    /** The reason of a closed event's {@code refusal} field, or null for any other value. */
    public static Reason fromWire(String wire) {
      for (Reason r : values()) {
        if (r.wire.equals(wire)) {
          return r;
        }
      }
      return null;
    }
  }

  private final Reason reason;
  private final int closeCode;

  /**
   * @param reason {@code "revoked"}, {@code "pending"} or {@code "other"}
   * @param closeCode the close code the host sent, 0 for {@code "other"} when only the reason is known
   */
  public TendrilRefusedException(String reason, int closeCode, String message) {
    super(message);
    Reason parsed = Reason.fromWire(reason);
    this.reason = parsed != null ? parsed : Reason.OTHER;
    this.closeCode = closeCode;
  }

  public Reason getReason() {
    return reason;
  }

  /**
   * The close code the host sent: 4001 for {@link Reason#REVOKED}, 4004 for {@link Reason#PENDING}.
   * For {@link Reason#OTHER} it is the code of a {@code closed} event (4400 to 4499), or 0 when the
   * exception comes from a failing call, which reports only the reason.
   */
  public int getCloseCode() {
    return closeCode;
  }

  /** The stable machine code: {@code refused_revoked}, {@code refused_pending} or {@code refused}. */
  public String getCode() {
    return reason.code;
  }
}
