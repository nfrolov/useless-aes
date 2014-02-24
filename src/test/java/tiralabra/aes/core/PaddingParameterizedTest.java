package tiralabra.aes.core;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class PaddingParameterizedTest {

    @Parameters
    public static Collection<Object[]> data() {
        final Collection<Object[]> data = new ArrayList<Object[]>();
        final int blockSize = 16;

        data.add(new Object[] {
            blockSize,
            new byte[] {
                (byte) 0x00
            },
            new byte[] {
                (byte) 0x00, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
                (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f
            }
        });

        data.add(new Object[] {
            blockSize,
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x08, (byte) 0x08
            }
        });

        data.add(new Object[] {
            blockSize,
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
            }
        });

        data.add(new Object[] {
            blockSize,
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
            },
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10,
                (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10, (byte) 0x10
            }
        });

        data.add(new Object[] {
            blockSize,
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00
            },
            new byte[] {
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f,
                (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f, (byte) 0x0f
            }
        });

        return data;
    }

    private Padding padding;

    private final int blockSize;
    private final byte[] message, paddedMessage;

    public PaddingParameterizedTest(int blockSize, byte[] message, byte[] paddedMessage) {
        this.blockSize = blockSize;
        this.message = message;
        this.paddedMessage = paddedMessage;
    }

    @Before
    public void setUp() {
        this.padding = new Padding();
    }

    @Test
    public void testPad() {
        byte[] messageCopy = Arrays.copyOf(message, message.length);
        byte[] actual = padding.pad(message, blockSize);
        assertThat("input message has been modified", message, is(equalTo(messageCopy)));
        assertThat(actual, is(equalTo(paddedMessage)));
    }

    @Test
    public void testUnpad() {
        byte[] paddedMessageCopy = Arrays.copyOf(paddedMessage, paddedMessage.length);
        byte[] actual = padding.unpad(paddedMessage, blockSize);
        assertThat("input message has been modified", paddedMessage, is(equalTo(paddedMessageCopy)));
        assertThat(actual, is(equalTo(message)));
    }

}
