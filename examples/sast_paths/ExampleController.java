import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

// Synthetic analysis input; not a production file-serving endpoint.
public class ExampleController {
    public String read(String fileName) throws IOException {
        return readFile(fileName);
    }

    private String readFile(String fileName) throws IOException {
        return Files.readString(Path.of(fileName));
    }
}
