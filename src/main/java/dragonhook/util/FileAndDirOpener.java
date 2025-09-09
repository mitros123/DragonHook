package dragonhook.util;

import java.io.File;
import java.io.IOException;

public class FileAndDirOpener {

    public static void openDirectory(String path) {
        File directory = new File(path);

        if (!directory.exists() || !directory.isDirectory()) {
            System.err.println("Invalid directory: " + path);
            return;
        }

        String os = System.getProperty("os.name").toLowerCase();

        try {
            if (os.contains("win")) {
                // Windows
                Runtime.getRuntime().exec(new String[]{"explorer.exe", directory.getAbsolutePath()});
            } else if (os.contains("mac")) {
                // macOS
                Runtime.getRuntime().exec(new String[]{"open", directory.getAbsolutePath()});
            } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
                // Linux/Unix
                Runtime.getRuntime().exec(new String[]{"xdg-open", directory.getAbsolutePath()});
            } else {
                System.err.println("Unsupported OS: " + os);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void openFile(String path) {
        File file = new File(path);

        if (!file.exists() || !file.isFile()) {
            System.err.println("Invalid file: " + path);
            return;
        }

        String os = System.getProperty("os.name").toLowerCase();

        try {
            if (os.contains("win")) {
                // Windows
                Runtime.getRuntime().exec(new String[]{"explorer.exe", file.getAbsolutePath()});
            } else if (os.contains("mac")) {
                // macOS
                Runtime.getRuntime().exec(new String[]{"open", file.getAbsolutePath()});
            } else if (os.contains("nix") || os.contains("nux") || os.contains("aix")) {
                // Linux/Unix
                Runtime.getRuntime().exec(new String[]{"xdg-open", file.getAbsolutePath()});
            } else {
                System.err.println("Unsupported OS: " + os);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    
}
