import React from "react";

export default function BackgroundVideo({
    src = "/bg-video.mp4",
    overlayOpacity = 0.75,
}) {
    return (
        <div className="fixed inset-0 w-full h-full -z-10 overflow-hidden pointer-events-none">
            <video
                autoPlay
                loop
                muted
                playsInline
                className="w-full h-full object-cover"
            >
                <source src={src} type="video/mp4" />
            </video>

            {/* Dark Overlay matching QuantumShield theme */}
            <div
                className="absolute inset-0 bg-[#0C0E12]"
                style={{ opacity: overlayOpacity }}
            />
        </div>
    );
}
