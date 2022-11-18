import encryption.Mode;
import ui.Window;

import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        new Window(Mode.AES);
        new Window(Mode.DES);
    }
}
