package sasl.mechanism.did.messages;

import java.util.Objects;

public abstract class SASLMessage {

    private final byte[] messageBytes;
    private final String message;

    protected SASLMessage(byte[] messageBytes, String message) {
        this.messageBytes = messageBytes;
        this.message = message;
    }

    public byte[] getMessageBytes() {
        return messageBytes;
    }

    public String getMessage() {
        return message;
    }

    @Override
    public String toString() {
        return "SASLMessage{" +
                "message='" + message + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        SASLMessage that = (SASLMessage) o;
        return Objects.equals(message, that.message);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(message);
    }
}
