package kopo.poly.util;

public class ExtractImageUtil {
    public static String extractImageId(String url) {
        String[] parts = url.split("atchFileId=");
        return parts.length > 1 ? parts[1].split("&")[0] : "";
    }
}
